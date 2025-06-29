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
  - в расширенном смысле харденинг = обязательные варнинги + ограничения на деплой + проверки в рантайме (в компиляторе или библиотеках)
    * варнинги: обычно `-Wall -Wformat -Werror` плюс несколько дополнительных
    * деплой:
      + не поставлять программу с отладочной информацией (использовать separate debug info) или символьной таблицей
      + скрыть приватные символы из динамической таблицы символов

# (2) Исчерпывающее перечисление: stack protector, pie, cfi, minimal ubsan, fortify, etc.

Time: 15 мин.
Assignee: Юрий

Buffer overflow атаки (в хронологическом порядке):
  - stack smashing
    * запись кода в стек и вызов через return
    * неактуальна из-за noexecstack, W^X, etc.
  - return-to-libc
    * вызов стандартной функции типа `system(3)` через return
    * особенно хорошо работало на 32-битном x86, т.к. аргументы передавались на стеке
    * для amd64 нужны гаджеты (ROP)
  - return-oriented programming
    * state-of-the-art, наиболее актуальная проблема

ASLR:
  - случайное расположение частей программы в адресном пространстве
    * стек, куча, статические данные, код библиотек
  - специальный флаг `-fPIE` заставляет собрать приложение в специальном "перемещаемом" (position-independent) виде
    * `-fPIE` = `-fPIC` + доп. оптимизации (связанные с невозможностью runtime interposition)
    * инструкции не используют абсолютные адреса
    * теперь ядро может перемещать сегмент кода при старте программы
  - существенно снизил вероятность атак return-to-libc и ROP
  - распространённость:
    * TODO: посчитать сколько buffer overflow CVE в 2024 ?
  - эквивалентные отладочные проверки:
    * Valgrind и Asan обнаруживают причину подобных ошибок (buffer overflow)
  - проблемы:
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
    * TODO
  - сравнение с безопасными языками:
    * та же техника используется в Rust
    * для Java не так актуальна, т.к. JIT-код и так рандомизируется
  - как включить:
    * опция `-fPIE` (GCC, Clang), `/DYNAMICBASE` (Visual Studio)
    * включена по умолчанию в компиляторах в современных дистрибутивах (Ubuntu/Debian, Fedora, Gentoo)
      + можно отключить флагом `-no-pie`

Неисполняемый стек:
  - aka W^X, aka NX bit, aka Data Execution Prevention
    * первая hardening защита
    * впервые появились в OpenBSD (2003) и Windows (2004)
  - отключает возможность исполнения кода в сегменте стека на уровене OS
  - ликвидирует stack smashing атаки как класс
  - распространённость:
    * TODO: посчитать сколько buffer overflow CVE в 2024 ?
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
    * в Java зависит от конкретной JDK
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
    * все современные дистро стараются использовать noexecstack по умолчанию
      + на моей системе execstack включён только у программ из пакета dpkg-query
        (`/usr/bin/lksh`, etc.)

Автоматическая инициализация:
  - инициализация всех локальных переменных (нулями для hardening, случайными значениями для debug)
  - виды атак:
    * TODO
  - эквивалентные отладочные проверки: Valgrind, Msan, [DirtyFrame](https://github.com/yugr/DirtyFrame)
  - распространённость:
    * TODO: посчитать сколько uninitialized CVE в 2024 ?
  - оверхед:
    * TODO
  - проблемы
    * TODO
  - сравнение с безопасными языками (Rust, возможно Java)
    * TODO
  - как включить:
    * флаг `-ftrivial-auto-var-init=zero` (GCC, Clang), [скрытый](https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html) [флаг](https://msrc.microsoft.com/blog/2020/05/solving-uninitialized-stack-memory-on-windows/) `-initall` (Visual Studio)

TODO:
  - CFI (ARM PAC, Intel CET)
    * verify static and dynamic types match
    * also checks for dynamic types for vcalls, C++ casts, etc.
    * компиляторная инструментация
    * проблемы при немонолитное иерархии (дети в других dso), нужна спец опция и перф оверхед)
    * новые аппаратные проверки (ARM PAC, ARM BTI ~ Intel IBT (часть Intel CET))
      + включаются по `-mbranch-protection`
  - Stack protector
    * ex-ProPolice, ex-StackGuard
    * windows `/GS-`
    * canary in coal mine (взять картинку)
    * в Clang также `-fsanitize=safe-stack` (разные стеки, также Intel Safe Stack (часть Intel CET))
    * также переупорядочивает переменные
  - Stack clashing (aka stack probes)
  - `_FORTIFY_SOURCE`
  - Проверки STL, в т.ч. индексации и итераторов (`_GLIBCXX_ASSERTIONS` в GCC, `_LIBCPP_HARDENING_MODE` в Clang)
  - Отключение опасных оптимизаций (`-fno-delete-null-pointer-checks`, `-fno-strict-overflow`, `-fno-strict-aliasing`)
  - Ограничения на динамическую линковку (relro, noplt, now, as-needed (to reduce ROPs))
  - Проверки целочисленного переполнения (UBSan с minimal runtime)
  - Опция `-fhardened`
  - `memset_s` and friends
  - Stack scrubbing (`-fstrub`)

Для каждой проверки:
  - суть
  - классы обнаруживаемых атак (примеры ?)
  - распространённость (анализ CVE)
  - эквивалентные отладочные проверки
  - оверхед (один и тот же бенч)
  - проблемы
  - сравнение с безопасными языками (Rust, возможно Java)
  - как включить
    * опции и макросы компилятора с подробным пояснением и примерами
    * ограничения на динамическую линковку
    * поддержка в дистрибутивах и тулчейнах
      + что включено по умолчанию (PIE, `_FORTIFY_SOURCE`, `-Wl,-z,now`, `-Wl,-z,relro`, etc.)
      + что включено для пакетов дистра и что в компиляторе
      + см. про дистры в https://en.m.wikipedia.org/wiki/Buffer_overflow_protection#GNU_Compiler_Collection_(GCC)

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
