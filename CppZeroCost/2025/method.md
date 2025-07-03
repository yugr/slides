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
    * false positives и false negatives (искать "bypassing FEATURE")
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
  - использование в реальных проектах (дистрах и т.д.)

TODO: прочитать:
  - https://fedoraproject.org/wiki/Security_Features_Matrix
  - https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options
  - https://wiki.ubuntu.com/Security/Features
  - https://wiki.gentoo.org/wiki/Project:Hardened
  - https://github.com/rust-lang/rust/issues/15179
  - примеры атак: https://guyinatuxedo.github.io
  - https://www.reddit.com/r/cpp/comments/1bafd7b/compiler_options_hardening_guide_for_c_and_c/
