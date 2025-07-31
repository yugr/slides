Разные методологические решения по слайдам.

Все утверждения ниже даны для последних версий дистров:
  - Debian 12 (bookworm)
    * [Debian](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options)
    * дефолтные флаги пакетов берутся из [dpkg-dev](https://packages.debian.org/bookworm/dpkg-dev)
      + [git](https://salsa.debian.org/dpkg-team/dpkg)
      + пакетные флаги можно посмотреть, вызвав `dpkg-buildflags(1)`
      + по умолчанию пакеты собираются с hardened-опциями:
        ```
        commit e49be6015dcdcc3ef62ab6bbf58de5053e7dd8ad
        Author: Guillem Jover <guillem@debian.org>
        Date:   Mon Mar 28 00:46:36 2016 +0200

        debian: Enable all hardening flags

        Starting with gcc-5 there is no performance loss when enabling PIE on
        i386, so there is no point in not enabling it.

        +       DEB_BUILD_MAINT_OPTIONS="hardening=+all,$(hardening_old)" \
        ```
  - Ubuntu 24.04 (noble)
    * [Ubuntu](https://wiki.ubuntu.com/Security/Features)
    * дефолтные флаги пакетов берутся из [dpkg-dev](https://launchpad.net/ubuntu/noble/+package/dpkg-dev)
      + [wiki](https://wiki.ubuntu.com/ToolChain/CompilerFlags)
      + [git](https://git.launchpad.net/ubuntu/+source/dpkg)
      + по умолчанию пакеты собираются с hardened-опциями (унаследовано от Debian)
  - Fedora 42
    * [Fedora](https://fedoraproject.org/wiki/Security_Features_Matrix)
    * дефолтные флаги пакетов берутся из [redhat-rpm-config](https://src.fedoraproject.org/rpms/redhat-rpm-config)
      (коммит 0ec772ce для Fedora 42)
      + по умолчанию пакеты [собираются](https://fedoraproject.org/wiki/Changes/Harden_All_Packages) с hardened-опциями:
        ```
        %_hardened_build       1
        ```
        в `macros`
  - TODO: RedHat, OpenSUSE, Gentoo
  - TODO: Android, Windows, macOS, BSDs

Сравнение с другими языками:
  - рассматриваем только статические языки (не JIT)
  - Rust
  - TODO: Swift, Ada, Solidity ?

Для каждой защиты нужно описать
  - суть
  - пример ошибки
  - целевые уязвимости и распространённость (анализ CVE/KVE)
  - история (optional)
  - возможные расширения
  - эквивалентные отладочные проверки
  - оверхед
    * процитировать известные результаты
    * использовать один и тот же бенч
  - проблемы:
    * false positives и false negatives (искать "bypassing FEATURE", "weakness of FEATURE")
    * поддержка динамических библиотек
    * поддержка на разных платформах
  - сравнение с безопасными языками
    * Rust
  - как включить
    * опции и макросы компилятора с подробным пояснением и примерами
    * ограничения на динамическую линковку
    * поддержка в дистрибутивах и тулчейнах
      + что включено по умолчанию (PIE, `_FORTIFY_SOURCE`, `-Wl,-z,now`, `-Wl,-z,relro`, etc.)
  - ссылка на хорошую статью
  - использование в реальных проектах (дистрах, браузерах и т.д.)
    * что включено для пакетов дистра и что в компиляторе (и в GCC, и в Clang)
      + проверить по https://github.com/jvoisin/compiler-flags-distro
    * можно автоматизировать поиск с помощью https://github.com/slimm609/checksec или `scanelf -lpqe`
    * TODO: как просканировать все пакеты дистрибутива (без установки ?)
  - опции сборки критического софта:
    * suids, браузеры, чаты и почтовые клиенты, интерпретаторы (Python, PHP, bash), БД, pdf/image-читалки, OpenOffice, etc.
    * браузеры:
      + Chrome:
        - https://chromium.googlesource.com/chromium/src/+/refs/heads/main/build/config (тег `140.0.7313.1` или коммит d0273f3d)
        - https://chromium.googlesource.com/chromium/src/+/HEAD/docs/system_hardening_features.md
      + Firefox:
        - https://github.com/mozilla-firefox/firefox/blob/main/build/moz.configure (тег `FIREFOX_142_0b1_RELEASE` или коммит b0ca903b)

Бенчмаркинг:
  - тестировалась компиляция самого тяжелого файла (`CGBuiltin.cpp`) с помощью Clang llvmorg-20.1.7 с дефолтными флагами (`-O3 -DNDEBUG`)
  - Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz (дефолтные настройки)
  - ОС Debian 12 (bookworm)
  - [скрипты запуска](bench)

Подсчёт CVE/KEV-метрик:
  - [скрипт](scripts/cve_scanner.py) и [тоже скрипт](scripts/kev_scanner.py)

TODO: прочитать:
  - https://web.ist.utl.pt/nuno.lopes/pubs/ub-pldi25.pdf
  - https://www.usenix.org/system/files/sec23fall-prepub-123-xu-jianhao.pdf
  - Memory Tagging: A Memory Efficient Design
  - https://security.googleblog.com (все C++-relevant статьи)

TODO: поправить на слайдах:
  - список убранных защит (CFI, etc.)
  - Safe Coding - Google-specific
  - какой уровень фортификации у ffmpeg?
  - убрать историю relro
  - упомянуть регрессии в Rust от arith. checks
  - поправить выравнивание в hardening
  - уточнить про инициализацию переменных при erroneous behavior (Роман)
  - упомянуть Secure SDLC
  - не только vtable, но и dtors
  - Hardening vs Security (Роман)
    * Hardening - уменьшение поверхности атаки
    * Security - более широкая категория (обнаружение проникновений, обработка инцидентов, etc.)
  - упомянуть локальность стат. анализа (из https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#pro-profiles):
  ```
  A "profile" is a set of deterministic and portably enforceable subset of rules (i.e., restrictions) ...
  [that] require only local analysis and could be implemented in a compiler
  ```
  - другие примеры для safety profiles (из https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#pro-profiles):
    * narrowing promotions, negative float to unsigned
  - упомянуть про Safe Buffers в Chrome (Роман)
  - не нужно включать `-fsanitize=undefined` (3x по сравнению с integer overflow)
  - заменить "поставка" на "деплой"
  - убрать прокликаные ссылки из pdf
  - написать названия сегментов на фото с контейнерами
  - поправить пример с erroneous behavior (Роман)
  - формулировки на слайде с UB/EB/etc.: "новый тип поведения", "некоторые типы поведения" (Роман)
  - комментарий к примеру в секции про небезопасные оптимизации
  - убрать (1) и (2) на слайде про недостатки ASLR
  - выровнять hardened_malloc в таблице Rust
  - добавь про AArch64 TBI
  - `shstk` включается аппаратно по атрибуту бинарного файла (инструментация в компиляторе не нужна)
  - добавить Go в список MSL
  - указать авторов картинок
  - убрать лишние слайды
  - перенести мотивацию buffer overflow в начало
  - добавить Рому в благодарности ("Роман Лебедев (Spectral::Technologies)")
  - MSL -> Memory Safe Languages
  - добавить сколько unsafe-кода в Rust stdlib::core, etc.
  - CFI также защищает от vptr smashing
  - vptr smashing (vtable hijacking), atexit hijacking
  - замечания Лизы
