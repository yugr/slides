# (0) Представление, введение в проблематику, план доклада

Time: 3 мин.
Assignee: Роман

- почему safety & security сейчас так актуально для С++
  * статистика ошибок memory & integer overflow
  * 70% ошибок в Microsoft и Chrome это ошибки памяти
    + см. ссылки в [статье OpenSSF](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html)
  * не все ошибки приводят к уязвимостям (CVE), но ~70% 0-days это баги памяти
    + см. [презентацию Wheeler](https://docs.google.com/presentation/d/1EDQL-6MUKrqbILBtYjpiF96uW5LXcnIuE-HxzyCIr68/edit?slide=id.g2ddb8e6973c_0_7#slide=id.g2ddb8e6973c_0_7)
  - многие заказчики (в т.ч. государственные) требуют обязательного использования hardening или безопасных языков
- какие движения в этом направлении
- цель и план доклада

# (1) Что такое hardening и в чем его принципиальное отличие от других средств отладки

Time: 5 мин.
Assignee: Роман

- пример с некорректным выводом (`_FORTIFY_SOURCE`, проверки stl)
- в чем суть
  * универсальная концепция (дополнительная безопасность в проде)
- чем он отличается от asan/valgrind/fuzzing
  * достаточно дешёвые проверки
  * более дорогие проверки должны делаться в QA (sanitizers, valgrind, static analysis, fuzzing, etc.)
  * замеры asan vs libc++ checks, `_FORTIFY_SOURCE`, stack protector vs normal

TODO:
  - в расширенном смысле харденинг = правила безопасной разработки + ограничения на деплой + проверки в рантайме (в компиляторе, библиотеках, ядре ОС)
    * безопасная разработка:
      +  `memset_s`, доп. варнинги, static analysis и т.п.
      + варнинги: обычно `-Wall -Wformat -Werror` плюс несколько дополнительных
    * безопасный деплой:
      + не поставлять программу с отладочной информацией (использовать separate debug info) или символьной таблицей
      + скрыть приватные символы из динамической таблицы символов
    * мы в докладе рассматриваем ТОЛЬКО рантайм-проверки в тулчейне (т.е. компиляторе и стд. библиотеках)
  - требования к харденинг: низкий оверхед + высокая точность (low false positive rate)

# (2) Исчерпывающее перечисление: stack protector, pie, cfi, minimal ubsan, fortify, etc.

Time: 15 мин.
Assignee: Юрий
Effort: 11h

Все утверждения ниже даны для этих версий дистров:
  - Debian GNU/Linux 11 (bullseye)
  - Ubuntu 22.04
  - Fedora 39
  - TODO: проверить на последних ?
  - TODO: RedHat ?
  - TODO: BSDs ?

Сравниваемся только с Rust, т.к. в Java основную роль играет динамический код.

Buffer overflow атаки (в хронологическом порядке):
  - stack smashing
    * запись кода в стек и вызов через return
    * неактуальна из-за noexecstack, W^X, etc.
  - return-to-libc
    * вызов стандартной функции типа `system(3)` через return
    * вариант атаки: return-to-plt
    * особенно хорошо работало на 32-битном x86, т.к. аргументы передавались на стеке
    * для amd64 нужны гаджеты (ROP)
  - return-oriented programming
    * state-of-the-art, наиболее актуальная проблема
  - TODO: посмотреть атаки в https://www.ctfrecipes.com/pwn/stack-exploitation

ASLR:
  - случайное расположение частей программы в адресном пространстве
    * стек, куча, код библиотек
  - TODO: пример ошибки
  - специальный флаг `-fPIE` заставляет собрать приложение в специальном "перемещаемом" (position-independent) виде
    * `-fPIE` = `-fPIC` + доп. оптимизации (связанные с невозможностью runtime interposition)
    * инструкции не используют абсолютные адреса
    * теперь ядро может перемещать сегмент кода при старте программы
  - существенно снизил вероятность атак return-to-libc и ROP
  - TODO: история
  - классы атак и распространённость:
    * ~11% CVE в 2024 связаны с buffer overflow
    * 20% из них это stack overflow (самые опасные)
    * TODO: Mitre CWE Top 25 2023
    * TODO: CVEs in safe langs (Log4j) or social engineering (xz utils)
  - эквивалентные отладочные проверки:
    * Valgrind и Asan обнаруживают причину подобных ошибок (buffer overflow)
  - проблемы:
    * статические данные не рандомизируются (только базовый адрес приложения) => хакер знает смещение GOT и PLT таблиц и может атаковать их
      + см. про защиту GOT ниже
    * ASLR убила подход предлинковки библиотек (Prelink), который использовался для ускорения загрузки
    * достаточно знать базовый адрес одной или нескольких библиотек => уязвима к info leakage
      + например [format string attach](https://en.m.wikipedia.org/wiki/Uncontrolled_format_string)
    * рандомизация делается однократно при загрузке => уязвима к brute force (особенно на 32-битных платформах)
      + требуется регулярный рестарт сервисов
      + на Windows положение библиотек фиксируется при первом запуске приложения :)
  - расширения:
    * некоторые коммерческие тулчейны также рандомизируют порядок функций при линковке (Safe Compiler)
    * Moving Target Defense динамически переупорядочивает сегменты в рантайме
  - оверхед:
    * TODO: померять дефолтный бенч
  - сравнение с безопасными языками:
    * та же техника используется в Rust
  - как включить:
    * опция `-fPIE` (GCC, Clang), `/DYNAMICBASE` (Visual Studio)
    * включена по умолчанию в GCC/Clang в современных дистрибутивах (Ubuntu/Debian, Fedora, Gentoo)
      + можно отключить флагом `-no-pie`

Неисполняемый стек:
  - aka W^X, aka NX bit, aka Data Execution Prevention
    * первая hardening защита
    * впервые появились в OpenBSD (2003) и Windows (2004)
  - отключает возможность исполнения кода в сегменте стека на уровене OS
  - TODO: пример ошибки
  - классы атак и распространённость:
    * ~11% CVE в 2024 связаны с buffer overflow
    * 20% из них это stack overflow (самые опасные)
    * ликвидирует stack smashing атаки как класс
  - эквивалентные отладочные проверки:
    * Valgrind и Asan обнаруживают причину подобных ошибок (buffer overflow)
  - проблемы:
    * обойти защиту никак нельзя
    * работает только если все DSO в программе слинкованы без исполняемого стека
      + лучше всегда проверять все executables и libraries:
        ```
        # Не должно быть E (или X) в permissions
        $ readelf -lW myprog | grep GNU_STACK
        ...
          GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                         0x0000000000000000 0x0000000000000000  RW     0x10
        ...
        ```
      + если подгружается (через `dlopen`) проблемная библиотека,
        то до [недавнего времени](https://sourceware.org/bugzilla/show_bug.cgi?id=32653)
        она делала стек исполняемым
      + можно использовать `scanelf -lpqe` для поиска
  - расширения:
    * запрет исполнения не только для стека, но и для любых writable-сегментов
      + heap, static data
      + общее название идеи: W^X
  - оверхед отсутствует
  - сравнение с безопасными языками:
    * Rust работает аналогично C
  - как включить:
    * обычное использование
      + обычно компилятор просто сообщает линкеру о noexecstack с помощью
        ```
        .section .note.GNU-stack,"",@progbits
        ```
      + линкер включит noexecstack если все объектные файлы это разрешают
      + execstack требуется для ассемблерных файлов (в некоторых просто забыли указать
        директиву) и для GNU nested functions ([раньше](https://sourceware.org/bugzilla/show_bug.cgi?id=27220)
        использовались в Glibc)
        - TODO: почему использование Glibc не приводило к execstack ?
    * если линкер не справился то можно воспользоваться
      + опцией `-Wl,-z,noexecstack` в GCC/Clang, `/NXCOMPAT` в Visual Studio
      + отключить execstack в готовой программе с помощью утилиты `execstack(8)`
    * все современные дистро стараются использовать noexecstack по умолчанию в GCC и Clang
      + на моей системе execstack включён только у программ из пакета dpkg-query
        (`/usr/bin/lksh`, etc.)

Автоматическая инициализация:
  - инициализация всех локальных переменных (нулями для hardening, случайными значениями для debug)
  - TODO: виды атак
  - TODO: пример ошибки
  - TODO: история
  - TODO: расширения
  - TODO: что будет в C++26 (@Роман):
    * `[[indeterminate]]`
    * [P2795](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2795r3.html#proposal))
    * [P2723](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2723r1.html)
  - эквивалентные отладочные проверки: Valgrind, Msan, [DirtyFrame](https://github.com/yugr/DirtyFrame)
  - классы атак и распространённость:
    * около 50 uninitialized variable CVE в 2024 (1% от buffer overflow CVE)
  - оверхед:
    * [1% на Firefox](https://serge-sans-paille.github.io/pythran-stories/trivial-auto-var-init-experiments.html)
    * may take over 10% on hot paths:
      + [virtio](https://patchwork-proxy.ozlabs.org/project/qemu-devel/patch/20250604191843.399309-1-stefanha@redhat.com/)
      + [Chrome](https://issues.chromium.org/issues/40633061#comment142)
    * TODO: померять дефолтный бенч
  - проблемы
    * существенный оверхед
    * ломает обнаружение багов в Valgrind и Msan
    * инициализация нулями не всегда даёт осмысленный результат (мы скорее скрываем проблему, а не фиксим)
    * применяется только к локальным переменным (глобальные и так инициализируются, для кучи можно использовать Scudo hardened allocator)
  - сравнение с безопасными языками
    * Rust заставляет программиста инициализировать переменные (или явно использовать враппер `MaybeUninit`)
    * Java заставляет программиста инициализировать локальные переменные (динамическая память гарантированно зануляется)
  - как включить:
    * флаг `-ftrivial-auto-var-init=zero` (GCC, Clang), [скрытый](https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html) [флаг](https://msrc.microsoft.com/blog/2020/05/solving-uninitialized-stack-memory-on-windows/) `-initall` (Visual Studio)
    * не включён по умолчанию нигде

Защита таблиц диспетчеризации:
  - вызовы функции из динамических библиотек делаются через PLT-stubs
    * даже если библиотека вызывает свои собственные функции (см. доклад про оптимизации)
    * PLT stubs читают и обновляют таблицу указателей на функции
    * таблицу приходится держать в writable-сегменте => у хакеров есть возможность её модифицировать
    * флаги линкера `-Wl,-z,now -Wl,-z,relro` (т.н. "Full RELRO") заставляют дин. загрузчик
      + инициализировать содержимое таблиц на старте программы (`-z,now`)
      + пометить сегмент readonly (`-z,relro`)
    * доп. преимущество - нет проблемы с отложенными ошибками ненайденных символов
  - TODO: пример ошибки
  - история:
    * подход RELRO уже использовался ранее для однократно инициализируемых таблиц (vtables)
      + см. [статью Ian Lance Taylor](https://www.airs.com/blog/archives/189)
    * потребовалась лишь небольшая адаптация для GOT
  - классы атак и распространённость: соответствующие CVE не найдены
    * значительно более редкая атака чем buffer overflow, но вполне реальная:
      + смещение GOT/PLT известно
      + хакер с помощью ROP может поменять их и сделать return-to-plt
  - эквивалентные отладочные проверки:
    * не существуют (ни Valgrind, ни санитары не защищают от перезаписи GOT)
  - оверхед
    * известные результаты не найдены
    * TODO: померять дефолтный бенч
  - проблемы:
    * замедленное время стартапа (на разрешение символов)
    * некоторые программы могут сломаться (если в них были отсутствующие символы, которые не вызывались)
    * пользовательские таблицы функций не защищены (важно ли это ?)
  - сравнение с безопасными языками
    * Rust [использует](https://github.com/rust-lang/rust/issues/29877) Full RELRO
  - как включить
    * указать опции линкера: `-Wl,-z,now -Wl,-z,relro`
    * поддержка в дистрибутивах и тулчейнах:
      + Debian: не включены по умолчанию ни в GCC, ни в Clang (пакеты дефолтно видимо [собираются с partial RELRO](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options))
      + Ubuntu: включены по умолчанию в GCC, но только `-z relro` в Clang (partial RELRO)
      + Fedora: не включены по умолчанию ни в GCC, ни в Clang (но пакеты дефолтно [собираются с RELRO](https://fedoraproject.org/wiki/Security_Features_Matrix#Built_with_RELRO), правда непонятно full или partial)
      + что включено по умолчанию (PIE, `_FORTIFY_SOURCE`, `-Wl,-z,now`, `-Wl,-z,relro`, etc.)
  - ссылка на статью:
    * https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro

Уменьшение зависимостей:
  - часто программа линкует лишние библиотеки (например из-за устаревших билдскриптов)
  - от них можно избавиться без ручной модификации Makefiles с помощью флагов `-Wl,--as-needed`
    * [иногда](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html#allow-linker-to-omit-libraries-specified-on-the-command-line-to-link-against-if-they-are-not-used)
      также рекомендуют флаг `-Wl,--no-copy-dt-needed-entries`, но во-первых он не влияет на безопасность,
      а во-вторых и так включён по умолчанию в современных линкерах
  - обычно эти опции используют только для ускорения стартапа, но у них есть вторичный эффект:
    * уменьшается число доступных хакеру библиотек (для поиска гаджетов)
  - могут быть полезны против всех stack overflow атак, полагающихся на ROP
  - классы атак и распространённость (анализ CVE):
    * те же атаки что у неисполняемого стека
    * stack overflow, ROP programming
  - эквивалентные отладочные проверки: те же что у неисполняемого стека
  - TODO: история
  - TODO: расширения
  - оверхед: отсутствует (наоборот, стартап может ускориться)
  - проблемы:
    * могут сломаться некоторые программы
      + например которые использовали символы отброшенных либ с помощью `dlsym`
  - сравнение с безопасными языками
    * Rust компилируется только с `--as-needed` (как и GCC/Clang)
  - как включить
    * опция линкера `-Wl,--as-needed`
    * включена по умолчанию в GCC в Debian и Ubuntu, но не в Fedora
      + TODO: что с дефолтной сборкой пакетов в Fedora ?
    * не включена по умолчанию в Clang нигде
  - ссылка на хорошую статью: https://wiki.gentoo.org/wiki/Project:Quality_Assurance/As-needed

Stack protector:
  - рядом с return address на стеке размещается специальное случайное число ("канарейка")
    * переполнение буфера это memcpy, поэтому он не может изменить RA, не изменив канарейку (а её значение неизвестно)
    * также переупорядочивает переменные: скаляры кладутся ниже по стеку чем массивы
      + чтобы при переполнении массива нельзя было модифицировать флаги и т.п.
  - TODO: пример ошибки
  - классы атак и распространённость:
    * позволяет обнаруживать переполнение буфера перед return и соответственно ломает return-to-libc и ROP
    * TODO: анализ CVE
  - TODO: расширения
  - история
    * одна из первых проверок
    * также известны как stack canaries (взять картинку "canary in coal mine")
    * ex-StackGuard (1997), ex-ProPolice (2001-2005, IBM)
    * StackProtector (RedHat, 2005)
    * StackProtector Strong (2012, Google)
    * почему так много вариантов?
      + вопрос в том какие функции инструментировать
      + `-fstack-protector-all` - все функции (надёжно, но медленно)
      + `-fstack-protector` - функции с достаточно длинными строковыми массивами на стеке (компромиссное решение)
      + `-fstack-protector-strong` - средний и наиболее популярный вариант:
        - функции с любыми (в т.ч. вложенными) массивами
        - функции, которые передают адрес на локальные переменные
        - и т.п.
  - эквивалентные отладочные проверки: Valgrind, Asan
  - оверхед
    * существенные накладные расходы:
      + загрузка значения канарейки
      + сохранение на стек
      + чтение и проверка перед return
    * известные результаты:
      + [`-fstack-protector-all` 0-9%](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43809.pdf)
      + [`-fstack-protector-strong` no overhead](https://zatoichi-engineer.github.io/2017/10/04/stack-smashing-protection.html)
    * TODO: померять дефолтный бенч
  - проблемы
    * уязвим к info leakage (если канарейка утекла, то защита неэффективна)
    * если канарейка хранится в том же сегменте что и стек, хакер может переписать и её
    * не защищает от переписывания указателей на функции на стеке
  - сравнение с безопасными языками
    * Rust:
        + вообще коду на Rust эта опция не требуется, но она полезна в случае вызова внешних библиотек
        + есть опция для включения (`-Z stack-protector`),
          но по дефолту [отключена](https://github.com/rust-lang/compiler-team/issues/841)
  - кaк включить:
    * флаг `-fstack-protector-strong` (GCC, Clang), `/GS` (Visual Studio)
    * включена по умолчанию в GCC в Ubuntu, но не в других дистрах
      + TODO: что с дефолтной сборкой пакетов в Debian и Fedora ?
    * в Clang не включена по умолчанию нигде
  - ссылки на статьи:
    * https://wiki.osdev.org/Stack_Smashing_Protector
    * https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard

Stack clashing (aka stack probes):
  - различные стеки и куча отделены друга от друга guard pages
    * незамапленными страницы, обращение к которым вызовет SEGV
    * ожидается что программа обратится к адреса на странице
      при создании стекового фрейма и stack overflow будет обнаружен
    * но что если на фрейме дежит очень большой (>4096 байтов) массив и
      мы как бы перепрыгиваем guard page ?
    * идея пройти по всему фрейму с шагом 4096 перед началом работы,
      чтобы гарантированно спровоцировать SEGV
  - TODO: классы атак и распространённость (анализ CVE)
  - TODO: история (optional)
    * [серия статей Qualys](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt) с proof of concept (2017)
  - TODO: возможные расширения
  - эквивалентные отладочные проверки: не существует
  - оверхед
    * [нет регрессий на Firefox](https://blog.llvm.org/posts/2021-01-05-stack-clash-protection/)
    * TODO: померять дефолтный бенч
  - TODO: проблемы
  - сравнение с безопасными языками
    * в Rust stack probing включён по умолчанию (по крайней мере на x86)
  - как включить
    * два флага: `-fstack-clash-protection` и устаревший `-fstack-check`
    * не включены по умолчанию в дистрах
  - ссылки на статьи:
    * https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background
    * https://developers.redhat.com/blog/2019/04/30/stack-clash-mitigation-in-gcc-why-fstack-check-is-not-the-answer
    * https://developers.redhat.com/blog/2020/05/22/stack-clash-mitigation-in-gcc-part-3

`-fhardened`:
  - зонтичная опция для всех hardened-оптимизаций
  - включает [все опции, рекомендованные OpenSSF](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html)
  - хороший дефолтный флаг, но пока реализован только в GCC
    * [Clang issue](https://github.com/llvm/llvm-project/issues/122687)
    * семантика может зависеть от версии компилятора
      + для GCC можно посмотреть функцию `print_help_hardened`, сейчас
        ```
        -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -ftrivial-auto-var-init=zero -fPIE -Wl,-z,now -Wl,-z,relro -fstack-protector-strong -fstack-clash-protection -fcf-protection=full
        ```

TODO:
  - Отключение опасных оптимизаций (`-fno-delete-null-pointer-checks`, `-fno-strict-overflow`, `-fno-strict-aliasing`)
  - Проверки целочисленного переполнения (UBSan с minimal runtime)
  - `_FORTIFY_SOURCE`
  - Проверки STL, в т.ч. индексации и итераторов (`_GLIBCXX_ASSERTIONS` в GCC, `_LIBCPP_HARDENING_MODE` в Clang)
  - `-fsanitize=safe-stack` (разные стеки, также Intel Safe Stack (часть Intel CET))
  - CFI (ARM PAC, Intel CET)
    * verify static and dynamic types match
    * also checks for dynamic types for vcalls, C++ casts, etc.
    * компиляторная инструментация
    * проблемы при немонолитное иерархии (дети в других dso), нужна спец опция и перф оверхед)
    * новые аппаратные проверки (ARM PAC, ARM BTI ~ Intel IBT (часть Intel CET))
      + включаются по `-mbranch-protection`
  - Stack scrubbing (`-fstrub`)
  - `-fzero-call-used-regs` (https://www.semanticscholar.org/paper/Clean-the-Scratch-Registers%3A-A-Way-to-Mitigate-Rong-Xie/6f2ce4fd31baa0f6c02f9eb5c57b90d39fe5fa13)
  - [Scudo allocator](https://llvm.org/docs/ScudoHardenedAllocator.html)
  - другие фичи [отсюда](https://fedoraproject.org/wiki/Security_Features_Matrix)

Для каждой проверки:
  - суть
  - пример ошибки
  - классы атак и распространённость (анализ CVE)
  - история (optional)
  - возможные расширения
  - эквивалентные отладочные проверки
  - оверхед
    * процитировать известные результаты
    * использовать один и тот же бенч
  - проблемы
  - сравнение с безопасными языками
    * Rust
    * возможно Java
  - как включить
    * опции и макросы компилятора с подробным пояснением и примерами
    * ограничения на динамическую линковку
    * поддержка в дистрибутивах и тулчейнах
      + что включено по умолчанию (PIE, `_FORTIFY_SOURCE`, `-Wl,-z,now`, `-Wl,-z,relro`, etc.)
      + что включено для пакетов дистра и что в компиляторе (и в GCC, и в Clang)
      + см. про дистры в
        - [Fedora](https://fedoraproject.org/wiki/Security_Features_Matrix)
        - [Debian](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options)
        - [Ubuntu](https://wiki.ubuntu.com/Security/Features)
        - https://en.m.wikipedia.org/wiki/Buffer_overflow_protection#GNU_Compiler_Collection_(GCC)
  - ссылка на хорошую статью

# (3) Hardening под капотом на примере LLVM

Time: 10 мин.
Assignee: Роман

- `_FORTIFY_SOURCE`
- проверки stl в libc++
- автоинициализация переменных
- stack protector
- stack probes
- minimal UBSan
- CFI, PAC

# (4) Дальнейшее развитие hardening

Time: 7 мин.

- отход от бескомпромиссного требования zero-cost abstractions
- перспектива существующих hardening-практик в Стандарте языка
- введение в язык профилей т.е. безопасных диалектов
- существующие инструменты миграции (`-Wunsafe-buffer-usage`)
