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

Для каждой проверки нужно описать
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

TODO: интегрировать слайды

TODO: прочитать:
  - https://web.ist.utl.pt/nuno.lopes/pubs/ub-pldi25.pdf
  - MTE:
    * https://source.android.com/docs/security/test/tagged-pointers
    * https://web.archive.org/web/20241016154235/https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/enhanced-security-through-mte
