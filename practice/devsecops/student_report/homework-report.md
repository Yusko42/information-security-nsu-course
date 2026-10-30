# Отчет о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедренной уязвимости

[Ссылка на отчёт о ДЗ 1](../../practice1/student_report/Отчёт.md)

Фрагмент уязвимого кода:

```java
@PostMapping(value = "/files/url-download")
public ResponseEntity<String> uploadFromUrl(@RequestParam String request) throws IOException {
    URI uri = URI.create(request);

    // if (!isAllowedAddress(uri)) {
    //     return ResponseEntity.badRequest().body("Недопустимый адрес");
    // }

    Path uploadPath = Paths.get(UPLOAD_DIR);
    Files.createDirectories(uploadPath);

    Path destination = uploadPath.resolve("downloaded-file-" + UUID.randomUUID());

    try (InputStream input = uri.toURL().openStream()) {
        Files.copy(input, destination);
    }

    return ResponseEntity.ok("Файл из URL сохранён: " + destination);
}
```

Исправление: перед открытием соединения адрес проверяется методом `isAllowedAddress`. Хост разрешается в IP-адрес, и запрос отклоняется, если адрес loopback (`127.0.0.0/8`, `::1`), wildcard (`0.0.0.0`), link-local (`169.254.0.0/16`, в том числе metadata-сервис облака) или приватный (`10/8`, `172.16/12`, `192.168/16`). URL без хоста тоже отклоняется.

```java
URI uri = URI.create(request);

if (!isAllowedAddress(uri)) {
    return ResponseEntity.badRequest().body("Недопустимый адрес");
}
...

private boolean isAllowedAddress(URI uri) throws IOException {
    String host = uri.getHost();
    if (host == null) { return false; }
    InetAddress address = InetAddress.getByName(host);

    return !address.isLoopbackAddress()
        && !address.isAnyLocalAddress()
        && !address.isLinkLocalAddress()
        && !address.isSiteLocalAddress();
}
```

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | `p/java` |

Команда запуска (Git Bash, Windows; из корня проекта `demoapplication`):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/work" -w /work semgrep/semgrep semgrep scan --config p/java --json --output /work/semgrep-report-pjava.json /work/src
```

Проверка покрытия: файл с уязвимостью присутствует в списке просканированных файлов, ошибок парсинга нет. 
Результат: да, файл присутствует.

### 2.2. Сканирование собственным правилом (вариант А)

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | собственное правило [`rules/custom-ssrf.yaml`](../../practice1/demo/demoapplication/rules/custom-ssrf.yaml) |

Команда запуска (одинаковая для обеих версий; из корня проекта `demoapplication`):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/work" -w /work semgrep/semgrep semgrep scan --config /work/rules --json --output /work/semgrep-report.json /work/src
```

> `MSYS_NO_PATHCONV=1` отключает автоматическую конвертацию путей в Git Bash, а `$(pwd -W)` передает Docker путь в формате `C:/...`.

Проверка покрытия: **да**. В обоих отчетах `paths.scanned` содержит `/work/src/main/java/nsu/security/demoapplication/controller/FileController.java`, а `errors` пустой (`[]`), то есть ошибок парсинга и загрузки правил нет. Всего просканировано 7 Java-файлов.

Приложенные отчеты сканера:

- Уязвимая версия, `p/java`: [`semgrep-report-pjava.json`](./semgrep-report-pjava.json)
- Уязвимая версия, собственное правило: [`semgrep-report-have-error.json`](./semgrep-report-have-error.json)
- Исправленная версия, собственное правило: [`semgrep-report-no-error.json`](./semgrep-report-no-error.json)

## 3. Результаты сканирования

| Версия | Набор правил | Результат | Правило |
| --- | --- | --- | --- |
| Уязвимая | `p/java` | **FN** | `—` |
| Уязвимая | собственное правило | **TP** | `rules.spring-ssrf-uri` |
| Исправленная | собственное правило | **TN** | `—` |

### 3.1. Уязвимая версия

**`p/java`:** находок по CWE-918 нет. 

Обоснование классификации: **FN**, потому что сканер не обнаружил SSRF ни в источнике (строка 73), ни в синке (строка 85).

**Собственное правило.** Фрагмент находки из `semgrep-report-have-error.json`:

| Поле | Значение |
| --- | --- |
| ID правила | `rules.spring-ssrf-uri` |
| CWE | CWE-918: Server-Side Request Forgery (SSRF) |
| Файл | `src/main/java/nsu/security/demoapplication/controller/FileController.java` |
| Строка | 85 (столбцы 34–45, выражение `uri.toURL()`) |
| Сообщение сканера | User input is used as a URL for an outbound request without validating the address (SSRF). Validate the URI using isAllowedAddress(...) before opening the connection. |

Обоснование классификации: **TP**. Срабатывание указывает на строку `uri.toURL().openStream()`, то есть на ту же цепочку потока данных, что и внедренная уязвимость. CWE правила (CWE-918) совпадает с типом уязвимости. Уязвимость реально эксплуатируется: запрос с ДЗ 1 заставляет сервер выполнить запрос на скачивание файла с другого сервера от своего имени.

### 3.2. Исправленная версия

Находок нет: `semgrep-report-no-error.json` содержит `"results": []` и `"errors": []`.

Обоснование классификации: **TN**. Исправление корректно для заявленной модели угрозы (запрет loopback, link-local и приватных адресов), и правило учитывает проверку `isAllowedAddress(uri)` как санитайзер, поэтому срабатывание исчезло.

## 4. Анализ результатов

### 4.1. Как сработало правило (для TP)

- **Источник в правиле:** параметр метода с Spring-аннотацией `@RequestParam`, `@RequestBody`, `@PathVariable`, `@RequestHeader`, `@CookieValue` или `@ModelAttribute`: `$M(..., @$REQ $T $SRC, ...)`.
- **Синк в правиле:** `$U.toURL()`, `$U.openStream()`, `$U.openConnection(...)`, `new java.net.URL(...)`.
- **Соответствие коду:**
  - строка 73: `@RequestParam String request` — источник;
  - строка 74: `URI.create(request)` — taint переходит с `request` на `uri` (по умолчанию Semgrep распространяет taint через результат вызова);
  - строка 85: `uri.toURL().openStream()` — синк, находка на `uri.toURL()`.

### 4.2. Почему уязвимость не найдена (для FN)

- **Правило, которое должно было покрыть уязвимость:** [`java.spring.security.injection.tainted-url-host`](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-url-host.yaml), единственное Java-правило в `semgrep-rules` с CWE-918.
- **Причина расхождения:** **синк не входит в правило**.
- **Подробное объяснение:**
  - Источник правила (`@RequestParam` с нечисловым типом) совпадает с кодом, строка 73.
  - Синки правила:
    1. `new URL($ONEARG)`;
    2. ручная сборка URL-строки (`+`, `concat`, `StringBuilder.append`, `+=`, `String.format`), причем шаблон строки должен соответствовать регулярному выражению `http(s?)://%(v|s|q).*`, например `"http://%s/api"`.
  - В коде URL создается через `URI.create(request)`, а соединение открывается через `uri.toURL().openStream()`. Ни `URI.create`, ни `URI.toURL()`, ни `URL.openStream()` правило синками не считает, поэтому taint-путь от источника до синка не строится.
  - Правило рассчитано на сценарий, когда пользователь влияет на хост внутри строки-шаблона. Сценарий "Эпользователь задает URL целиком" покрыт только конструктором `new URL(...)`.

## 5. Доработка (если подходящего правила нет)

Выбранный вариант: **А**

### Вариант А. Собственное правило

Файл правила: [`custom-ssrf.yaml`](../../practice1/demo/demoapplication/rules/custom-ssrf.yaml)

```yaml
rules:
- id: spring-ssrf-uri
  languages: [java]
  severity: ERROR
  message: >-
    User input is used as a URL for an outbound request
    without validating the address (SSRF). 
    Validate the URI using isAllowedAddress(...)
    before opening the connection.
  metadata:
    cwe: ['CWE-918: Server-Side Request Forgery (SSRF)']
    category: security
  mode: taint
  pattern-sources:
  - patterns:
    - pattern-either:
      - pattern-inside: |
          $M(..., @$REQ(...) $T $SRC, ...) { ... }
      - pattern-inside: |
          $M(..., @$REQ $T $SRC, ...) { ... }
    - metavariable-regex:
        metavariable: $REQ
        regex: ^(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)$
    - focus-metavariable: $SRC
  pattern-sanitizers:
  - by-side-effect: true
    patterns:
    - pattern: isAllowedAddress($X)
    - focus-metavariable: $X
  pattern-sinks:
  - patterns:
    - pattern: $U.toURL()
    - focus-metavariable: $U
  - patterns:
    - pattern-either:
      - pattern: $U.openStream()
      - pattern: $U.openConnection(...)
    - focus-metavariable: $U
  - pattern: new java.net.URL(...)
```

Логика правила:

- **Источник:** параметр контроллера с Spring-аннотацией получения данных из запроса. Источник взят из `tainted-url-host` без ограничения на тип, так как URL всегда строка.
- **Синк:** места, где реально открывается исходящее соединение: `toURL()`, `openStream()`, `openConnection()`, `new URL(...)`. `URI.create(...)` и `new URI(...)` сознательно **не** являются синками: они вызываются до проверки адреса, и правило давало бы FP на исправленной версии.
- **Санитайзер:** вызов `isAllowedAddress($X)` с `by-side-effect: true`. После вызова переменная `$X` (здесь `uri`) считается очищенной во всем последующем коде метода, поэтому `uri.toURL()` после проверки не помечается.

Результаты запуска правила:

| Версия | Результат | Комментарий |
| --- | --- | --- |
| Уязвимая | **TP** | 1 находка, строка 85 `uri.toURL()`, CWE-918; отчет `semgrep-report-have-error.json` |
| Исправленная | **TN** | 0 находок, санитайзер `isAllowedAddress(uri)` прерывает taint-путь; отчет `semgrep-report-no-error.json` |

Ограничения правила:

- Санитайзер срабатывает на сам вызов `isAllowedAddress(uri)`, а не на использование его результата. Вызов без `if` тоже «очистит» переменную, и правило промолчит (возможный FN). Сузить санитайзер можно, добавив `pattern-inside: if (!isAllowedAddress($X)) { ... }`.
- Санитайзер привязан к имени метода из этого проекта. Для других проектов список имен нужно расширять.
- HTTP-клиенты (`RestTemplate`, `WebClient`, `HttpClient`) в синки не включены.

## 6. Выводы

Стандартный набор `p/java` не обнаружил SSRF, хотя правило `tainted-url-host` существует. Его синки ограничены `new URL(...)` и сборкой URL по шаблону `http://%s`, а распространенная конструкция `URI.create(...).toURL().openStream()` не покрыта. Собственное taint-правило с расширенным списком синков и санитайзером `isAllowedAddress` нашло уязвимость (TP) и корректно распознало исправление (TN). Без санитайзера и с синком на `URI.create` оно давало бы FP. Практический вывод: отсутствие находок от готовых наборов правил не означает отсутствия уязвимости. Для ключевых классов уязвимостей стоит проверять, какие синки описаны в правилах, и дополнять их собственными правилами под API, которые использует проект.