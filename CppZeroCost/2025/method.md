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
  - ссылка на хорошую статью
  - использование в реальных проектах (дистрах, браузерах и т.д.)
    * что включено для пакетов дистра и что в компиляторе (и в GCC, и в Clang)
      + проверить по https://github.com/jvoisin/compiler-flags-distro
    * можно автоматизировать поиск с помощью https://github.com/slimm609/checksec или `scanelf -lpqe`
    * TODO:
      + проверить важные программы в дистрах (python, bash, suids, etc.)
      + как просканировать все пакеты дистрибутива (без установки ?)

Бенчмаркинг:
  - тестировалась компиляция самого тяжелого файла (`CGBuiltin.cpp`) с помощью Clang llvmorg-20.1.7 с дефолтными флагами (`-O3 -DNDEBUG`)
  - Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz (дефолтные настройки)
  - ОС Debian 12 (bookworm)
  - [скрипты запуска](bench)

TODO:
  - отдельный слайд про Rust
  - подсветить конфликты опций (в слайдах про недостатки)
  - опции сборки критического софта:
    * браузеры, чаты и почтовые клиенты, интерпретаторы (Python, PHP), БД, pdf/image-читалки, OpenOffice, etc.
    * добавить про дефолтные опции таких пакетов в соотв. разделы
  - можно ли заменить `-Wl,-z` на `-z` ?
  - исследовать ситуацию с `DEB_BUILD_HARDENING`
    * на Debian (включён для [уязвимых пакетов](https://wiki.debian.org/ReleaseGoals/SecurityHardeningBuildFlags) ?)
      + https://git.dpkg.org/cgit/dpkg/dpkg.git
    * на Ubuntu (включён по умолчанию ?)
  - GWP Asan, HW Asan, A/B тестирование
  - https://patchwork.ozlabs.org/project/glibc/patch/57CDAB08.8060601@samsung.com/
  - `-fstrict-flex-arrays=3`

TODO: прочитать:
  - https://hovav.net/ucsd/talks/blackhat08.html
  - https://people.eecs.berkeley.edu/~dawnsong/papers/Oakland13-SoK-CR.pdf
  - https://vvdveen.com/publications/RAID2012.pdf
  - https://stackoverflow.com/questions/34616086/union-punning-structs-w-common-initial-sequence-why-does-c-99-but-not (low prio)
  - https://android-developers.googleblog.com/2020/06/system-hardening-in-android-11.html
  - https://web.ist.utl.pt/nuno.lopes/pubs/ub-pldi25.pdf
  - атаки:
    * https://guyinatuxedo.github.io (low prio)
    * https://www.forrest-orr.net/post/a-modern-exploration-of-windows-memory-corruption-exploits-part-i-stack-overflows
    * https://www.jerkeby.se/newsletter/posts/history-of-rop/
  - CFI:
    * https://blog.trailofbits.com/2016/10/17/lets-talk-about-cfi-clang-edition/
    * https://developers.redhat.com/articles/2022/06/02/use-compiler-flags-stack-protection-gcc-and-clang
    * https://lwn.net/Articles/856514/
    * https://nebelwelt.net/blog/20181226-CFIeval.html
    * https://struct.github.io/cross_dso_cfi.html
    * https://maskray.me/blog/2022-12-18-control-flow-integrity
  - MTE:
    * https://source.android.com/docs/security/test/tagged-pointers
    * https://sipearl.com/wp-content/uploads/2023/10/SiPearl-White_Paper_Control_Flow_Integrity-on-Arm64.pdf
