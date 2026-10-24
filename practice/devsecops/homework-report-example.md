# Отчет о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедренной уязвимости

- **Тип уязвимости:** Path Traversal
- **CWE:** CWE-23
- **Файл и строки:** `main/java/nsu/security/demoapplication/controller/FileController.java`, строки <96–103>

- **Источник (откуда приходят недоверенные данные):** `@RequestParam String filename`
- **Синк (где данные используются опасно):** `Paths.get(UPLOAD_DIR).resolve(filename)`

Фрагмент уязвимого кода:

```java
  Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
  Resource resource = new FileSystemResource(filePath);
```

Кратко опишите исправление:

```java
  Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
  Path uploadDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();

  if (!filePath.startsWith(uploadDir)) {
      return ResponseEntity.badRequest().build();
  }
```

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | p/java |

Команда запуска:

```bash
docker run --rm -v "${PWD}/src:/src" -e SEMGREP_APP_TOKEN=<token> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```

Проверка покрытия: файл с уязвимостью присутствует в списке просканированных файлов, ошибок парсинга нет. 

Приложенные отчеты сканера:

- Уязвимая/исправленная версия: [`semgrep-report.json`](devsecops/semgrep-report.json)

## 3. Результаты сканирования

| Версия | Результат | Правило |
| --- | --- | --- |
| Уязвимая | FN | `—` |

### 3.1. Уязвимая версия

Обоснование классификации: **FN**, потому что сканер не нашел Path Traversal

### 3.2. Исправленная версия

Находки нет, исправлять нечего.

## 4. Анализ результатов

### 4.2. Почему уязвимость не найдена (для FN)

- **Правило, которое должно было покрыть уязвимость:** https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml
- **Причина расхождения:** **FN** недостаток в правиле
- **Подробное объяснение:** потому что правило ловит паттерн `(Paths $PATHS).get(...)`, в который должен попасть пользовательский ввод, а у меня в коде используется `Paths.get(UPLOAD_DIR)` - то есть в вызов метода передается только константа `UPLOAD_DIR`, а не `filename`, контролируемый пользователем

## 5. Доработка (если подходящего правила нет)

Выбранный вариант: Б

### Вариант Б. Новая уязвимость

- **Тип уязвимости и CWE:** Path Traversal
- **Правило сканера, под которое она подобрана:** https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml
- **Коммит уязвимой/исправленной версии:** Тот же код

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | p/java |

Команда запуска:

```bash
docker run --rm -v "${PWD}/src:/src" -e SEMGREP_APP_TOKEN=<token> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```

Проверка покрытия: файл с уязвимостью присутствует в списке просканированных файлов, ошибок парсинга нет

Приложенные отчеты сканера:

- Уязвимая/исправленная версия: [`semgrep-report.json`](devsecops/semgrep-report.json)

## 3. Результаты сканирования

| Версия | Результат | Правило |
| --- | --- | --- |
| Уязвимая | TP | [правило](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml) |
| Исправленная | FP | [правило](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml) |

### 3.1. Уязвимая версия

Фрагмент находки (заполняется для TP):

| Поле | Значение |
| --- | --- |
| ID правила | [правило](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml) |
| CWE | CWE-23 |
| Файл | `main/java/nsu/security/demoapplication/controller/FileController.java` |
| Строка | 107 |
| Сообщение сканера | Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path. |

Обоснование классификации: это TP, поскольку сканер верно определил тип уязвимости, локацию в коде, и уязвимость действительно эксплуатируется

### 3.2. Исправленная версия

Фрагмент находки (заполняется для FP):

| Поле | Значение |
| --- | --- |
| ID правила | [правило](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml) |
| CWE | CWE-23 |
| Файл | `main/java/nsu/security/demoapplication/controller/FileController.java` |
| Строка | 123 |
| Сообщение сканера | Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path. |

Обоснование классификации: Это FP, потому что я добавил валидацию имени файла по регулярному выражению в строке 119, но сканер этого не видит.

## 4. Анализ результатов

Заполните подразделы, соответствующие вашим результатам.

### 4.1. Как сработало правило (для TP)

- **Источник в правиле:** `$METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...)`
- **Синк в правиле:** `- pattern: (Paths $PATHS).get(...)`
- **Соответствие коду:** 106-107

### 4.3. Почему сканер не распознал исправление (для FP)

Я добавил валидацию имени файла по регулярному выражению в строке 119, но сканер этого не видит. Он ожидает использование `org.apache.commons.io.FilenameUtils.getName(...)`

## 6. Выводы

Правило на уязвимость Path traversal существует, но оно не рассматривает случай, когда конкатенация пути происходит после вызова `Paths.get()`, через метод `resolve`. Основной практический вывод - для полноценного охвата этого типа уязвимости правило нужно доработать, или рассмотреть другой сканер. Также сканер не видит промежуточную обработку данных до вызова уязвимого метода, из-за этого появилась FP находка после исправления через регулярное выражение.
