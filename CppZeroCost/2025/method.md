Разные методологические решения по слайдам.

Все утверждения ниже даны для последних версий дистров:
  - Debian 12 (bookworm)
    * [Debian](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options)
    * пакетные флаги можно посмотреть, вызвав `dpkg-buildflags(1)`
  - Ubuntu 24.04 (noble)
    * [Ubuntu](https://wiki.ubuntu.com/Security/Features)
    * [дефолтные компиляторные флаги](https://wiki.ubuntu.com/ToolChain/CompilerFlags)
  - Fedora 42
    * [Fedora](https://fedoraproject.org/wiki/Security_Features_Matrix)
    * пакетные флаги: https://rpmfind.net/linux/rpm2html/search.php?query=redhat-rpm-config
      + [Changes/Harden All Packages](https://fedoraproject.org/wiki/Changes/Harden_All_Packages)
  - TODO: RedHat, OpenSUSE, BSDs ?

Сравнение с другими языками:
  - рассматриваем только статические языки (не JIT)
  - Rust
  - TODO: Ada, Solidity ?

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
      + что включено для пакетов дистра и что в компиляторе (и в GCC, и в Clang)
      + проверить по https://github.com/jvoisin/compiler-flags-distro
  - ссылка на хорошую статью
  - использование в реальных проектах (дистрах, браузерах и т.д.)
    * можно автоматизировать поиск с помощью https://github.com/slimm609/checksec или `scanelf -lpqe`
    * TODO:
      + проверить важные программы в дистрах (python, bash, suids, etc.)
    + TODO: как просканировать все пакеты дистрибутива (без установки ?)

Бенчмаркинг:
  - тестировалась компиляция самого тяжелого файла (`CGBuiltin.cpp`) с помощью Clang llvmorg-20.1.7 с дефолтными флагами (`-O3 -DNDEBUG`)
  - Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz (дефолтные настройки)
  - ОС Debian 12 (bookworm)
  - [скрипты запуска](bench)

TODO:
  - отдельный слайд про Rust

TODO: прочитать:
  - https://hovav.net/ucsd/talks/blackhat08.html
  - https://people.eecs.berkeley.edu/~dawnsong/papers/Oakland13-SoK-CR.pdf
  - https://vvdveen.com/publications/RAID2012.pdf
  - https://stackoverflow.com/questions/34616086/union-punning-structs-w-common-initial-sequence-why-does-c-99-but-not (low prio)
  - примеры атак: https://guyinatuxedo.github.io (low prio)
