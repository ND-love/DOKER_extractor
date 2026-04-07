import argparse
import tarfile
import json
import os
import hashlib
import tempfile
import sys

def calculate_md5(file_path):
    """Считает MD5 хеш файла порциями, чтобы не грузить память."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def is_elf(file_path):
    """Проверяет файл на наличие сигнатуры ELF (магические байты)."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except IOError:
        return False

def is_executable(file_path):
    """Проверяет, установлен ли флаг исполнения у файла."""
    return os.access(file_path, os.X_OK)

def extract_and_merge_layers(tar_path, extract_dir):
    """
    Распаковывает исходный архив и последовательно накладывает слои друг на друга,
    игнорируя символические и жесткие ссылки для обхода ограничений безопасности Python на Windows.
    """
    def skip_links_filter(member, dest_path):
        # Если это ссылка (символическая или жесткая) - просто не извлекаем ее
        if member.issym() or member.islnk():
            return None 
        
        # Для остальных файлов применяем стандартный фильтр безопасности (если доступен)
        if hasattr(tarfile, 'data_filter'):
            return tarfile.data_filter(member, dest_path)
        return member

    def extract_safe(tar, path):
        """Безопасное извлечение с поддержкой новых и старых версий Python."""
        if hasattr(tarfile, 'data_filter'):
            tar.extractall(path=path, filter=skip_links_filter)
        else:
            # Запасной вариант для Python < 3.12
            members = [m for m in tar.getmembers() if not (m.issym() or m.islnk())]
            tar.extractall(path=path, members=members)

    # Шаг 1: Распаковка основного образа
    with tarfile.open(tar_path, 'r') as main_tar:
        extract_safe(main_tar, extract_dir)

    manifest_path = os.path.join(extract_dir, 'manifest.json')
    if not os.path.exists(manifest_path):
        raise FileNotFoundError("manifest.json не найден. Это точно образ от 'docker save'?")

    with open(manifest_path, 'r') as f:
        manifest = json.load(f)

    merged_dir = os.path.join(extract_dir, 'merged_rootfs')
    os.makedirs(merged_dir, exist_ok=True)

    # Шаг 2: Последовательная распаковка слоев (верхний перетирает нижний)
    layers = manifest[0]['Layers']
    for layer in layers:
        layer_tar_path = os.path.join(extract_dir, layer)
        with tarfile.open(layer_tar_path, 'r') as layer_tar:
            extract_safe(layer_tar, merged_dir)

    return merged_dir

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """
    Вызывает в цикле для создания терминального прогресс-бара.
    """
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    # \r возвращает курсор в начало строки, перезаписывая предыдущий вывод
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    # Переход на новую строку при завершении
    if iteration == total: 
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Утилита для анализа docker-образов. Распаковывает tar-архив, сливает слои, ищет ELF и +x файлы, считает их MD5."
    )
    parser.add_argument("tar_file", help="Путь к архиву образа (например, image.tar)")
    # Добавляем опциональный аргумент для указания файла вывода
    parser.add_argument("-o", "--output", default="hashes_output.txt", help="Имя текстового файла для вывода результатов")
    args = parser.parse_args()

    if not os.path.isfile(args.tar_file):
        print(f"[-] Ошибка: Файл '{args.tar_file}' не найден.")
        return

    print(f"[*] Анализ образа: {args.tar_file}")

    with tempfile.TemporaryDirectory() as tmpdir:
        print("[*] Распаковываем и сливаем слои (это может занять время)...")
        merged_rootfs = extract_and_merge_layers(args.tar_file, tmpdir)

        print("[*] Этап 1: Сканирование файловой системы...")
        target_files = []
        
        # Проход 1: Только собираем пути нужных файлов
        for root, dirs, files in os.walk(merged_rootfs):
            for file in files:
                file_path = os.path.join(root, file)

                if os.path.islink(file_path) or not os.path.isfile(file_path):
                    continue

                is_e = is_elf(file_path)
                is_x = is_executable(file_path)

                if is_e or is_x:
                    target_files.append((file_path, is_e, is_x))
                    
        total_files = len(target_files)
        if total_files == 0:
            print("[-] Подходящих файлов (ELF или +x) не найдено.")
            return

        print(f"[+] Найдено файлов для анализа: {total_files}")
        print("[*] Этап 2: Подсчет контрольных сумм...")
        
        results_to_write = []
        
        # Отрисовываем начальный пустой прогресс-бар (0%)
        print_progress_bar(0, total_files, prefix='Прогресс:', suffix='Выполнено', length=40)

        # Проход 2: Считаем хеши и обновляем интерфейс
        for i, (file_path, is_e, is_x) in enumerate(target_files):
            md5_sum = calculate_md5(file_path)
            rel_path = "/" + os.path.relpath(file_path, merged_rootfs).replace("\\", "/")
            
            tags = []
            if is_e: tags.append("ELF")
            if is_x: tags.append("+x")
            
            # Формируем строку и кладем в список, а не печатаем
            results_to_write.append(f"[{','.join(tags):^7}] {md5_sum}  {rel_path}\n")
            
            # Обновляем прогресс-бар
            print_progress_bar(i + 1, total_files, prefix='Прогресс:', suffix='Выполнено', length=40)

        # Сохранение в файл
        print(f"[*] Сохранение результатов в файл {args.output}...")
        with open(args.output, 'w', encoding='utf-8') as f:
            f.writelines(results_to_write)
            
        print(f"[+] Готово! Результаты успешно сохранены.")

if __name__ == "__main__":
    main()