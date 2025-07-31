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
  * замеры normal vs hardening (libc++ checks, `_FORTIFY_SOURCE`, stack protector) vs Asan:
    + Stack Protector: 2%
    + Fortify (`_FORTIFY_SOURCE=3`): 2%
    + STL checks (`_GLIBCXX_ASSERTIONS`): 3.5%
    + Asan: 4.7x

TODO(Роман):
  - в расширенном смысле харденинг - интегральная активность: правила безопасной разработки + ограничения на деплой + проверки в рантайме (в компиляторе, библиотеках, ядре ОС) + настройки ОС
    * правила безопасной разработки (и тестирования):
      + пример интегрального подхода: [Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
      + концепция Safe Coding ([Developer Ecosystems for Software Safety](https://dl.acm.org/doi/pdf/10.1145/3651621))
      + допустимые API (запрет `gets` и `rand`, предпочтение `memset_s` и т.п., [C4996](https://learn.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warning-level-3-c4996)
      + static analysis (в т.ч. обязательные варнинги помимо стандартных `-Wall -Wextra -Werror`, например `-Wformat=2 -Wconversion=2`, в Visual Studio есть спец. флаг `/sdl` для таких варнингов, контракты)
      + доп. проверки (asserts, контракты и т.п.)
      + пример неудачного внедения безопасных практик: [Updated Field Experience With Annex K — Bounds Checking Interfaces](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1969.htm (2015))
    * безопасный деплой:
      + не поставлять программу с отладочной информацией (использовать separate debug info) или символьной таблицей
      + скрыть приватные символы из динамической таблицы символов
    * мы в докладе рассматриваем ТОЛЬКО рантайм-проверки в тулчейне (т.е. компиляторе и стд. библиотеках)
      + mitigation, не prevention
  - требования к харденинг:
    + низкий оверхед
    + высокая точность (low false positive rate)
    + простота интеграции (например не ломают ABI)
    + совместимость разных зашит
  - слайд с выводами:
    + какие флаги включить у себя в проде
    + будущее развитие языка
  - ссылки:
    + Delivering Safe C++
  - C++ profiles:
    * локальный стат. анализа (из https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#pro-profiles):
      ```
      A "profile" is a set of deterministic and portably enforceable subset of rules (i.e., restrictions) ...
      [that] require only local analysis and could be implemented in a compiler
      ```
    * другие примеры для safety profiles (из https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#pro-profiles):
      + narrowing promotions, negative float to unsigned, unions

# (2) Исчерпывающее перечисление: stack protector, pie, cfi, minimal ubsan, fortify, etc.

Time: 15 мин.

Assignee: Юрий

Effort (likely 10-20% underestimated):
  * plan: 45h
  * slides: 32h

## Атаки (exploits)

Stack buffer overflow атаки (в хронологическом порядке):
  - Morris Worm (1988)
  - stack smashing
    * Smashing The Stack For Fun And Profit (Aleph One)
    * запись шеллкода в стек и вызов через return
    * неактуальна из-за noexecstack, W^X, etc.
  - return-to-libc
    * вызов стандартной функции типа `system(3)` через return
    * вариант атаки: return-to-plt
    * особенно хорошо работало на 32-битном x86, т.к. аргументы передавались на стеке
    * для amd64 нужны гаджеты (ROP)
  - return-oriented programming
    * state-of-the-art, наиболее актуальная проблема

Heap overflow атаки:
  - более сложные и разнообразные:
    * испортить данные в несвязанном буфере (например указатели на функции или на vtable)
    * поменять метаданные аллокатора, чтобы заставить его менять данные по произвольному адресу
      (например поменять адрес malloc hook и вызвать его при следующем malloc,
      House of Force)
      + по этой причине malloc hooks были удалены из Glibc

Распространённость buffer overflow-уязвимостей:
  - ~11% CVE и 6.5% KEV в 2024
  - 80% Memory Safety CVE и 46% KEV в 2024
  - 20% buffer overflow CVE это stack overflow (самые опасные)
  - 40% memory corruptions in exploits (!) - buffer overflow ([Google Project Zero](https://security.googleblog.com/2024/11/retrofitting-spatial-safety-to-hundreds.html))
  - [Mitre CWE Top 25 2024](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html): места 2, 6, 8, 20
  - [70% уязвимостей в продуктах MS - ошибки памяти](https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/)
  - [70% high/critical ошибок в Chromium - ошибки памяти](https://www.chromium.org/Home/chromium-security/memory-safety/)
  - важно однако понимать что многие критические уязвимости не связаны с памятью:
    * Log4Shell (уязвимость в безопасном языке из-за исполнения произвольного кода)
    * XZ Utils (социальная инженерия)

Уязвимости кучи (heap errors):
  - ~3.8% CVE и 7% KEV в 2024
    * не учтены heap overflow CVEs, которые попали в buffer overflow
  - [Mitre CWE Top 25 2024](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html): место 8
    * не учтены heap overflow KEVs, которые попали в buffer overflow

Другие виды уязвимостей:
  - любые ошибки памяти:
    * 13% CVE и 12% KEV в 2024
  - integer overflow:
    * ~1% CVE и 1.5% KEV в 2024
    * [Mitre CWE Top 25 2024](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html): место 23
  - неинициализированные данные:
    * 80 CVE (0.001%) и 0 KEV в 2024
    * скорее всего большая часть CVE отнесена к результирующим CWE (buffer overflow, etc.)

Некоторые указанные ниже методы можно детектировать в уже собранном приложении (или библиотеке)
с помощью утилиты `checksec` (но не все). Важно:
  - надо всё же перепроверять флаги сборки
  - собирать из git (в пакетах старая версия)

Статьи:
  - примеры атак: https://guyinatuxedo.github.io (low prio)
  - примеры атак на кучу: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
  - история атак на стек: https://www.jerkeby.se/newsletter/posts/history-of-rop/
  - история атак: https://vvdveen.com/publications/RAID2012.pdf
  - https://www.forrest-orr.net/post/a-modern-exploration-of-windows-memory-corruption-exploits-part-i-stack-overflows
  - про рынок 0-days: https://securitycryptographywhatever.com/2024/06/24/mdowd/
  - [Secure by Design: Google’s Perspective on Memory Safety](https://storage.googleapis.com/gweb-research2023-media/pubtools/7665.pdf)

## Методы QA

- Hardening - крайняя мера, надо стараться обнаруживать ошибки на этапе QA
- Asan: >= 2x
- Valgrind: 20-50x (https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind)
- Debug STL: 2x (personal experience)

## Неисполняемый стек

- aka W^X, aka NX bit, aka Data Execution Prevention
- суть проверки:
  * отключает возможность исполнения кода в сегменте стека на уровне OS
- пример ошибки:
  * классическая атака Stack Smashing приведена [здесь](exploits/stack-smash)
  * при использовании noexecstack стабильно получаем
    ```
    Segmentation fault (core dumped)
    ```
- история:
  * одна из первых hardening защит
  * впервые появились в OpenBSD (2003) и Windows (2004)
- целевые уязвимости и распространённость
  * ликвидирует stack smashing атаки как класс
  * см. статистику выше
- эквивалентные отладочные проверки:
  * Asan обнаруживает причину подобных ошибок, stack buffer overflow (Valgrind нет)
- проблемы:
  * false positives:
    + библиотеки или программы, которые полагаются на execstack
      (например GNU nested functions или просто забыли аннотировать асм),
      могут перестать работать
  * false negatives:
    + если защита включена, то обойти её хакерам не получится
    + решает только проблему stack smashing (самой базовой атаки типа stack overflow)
    + работает только если все DSO в программе слинкованы без исполняемого стека
      - в частности все `.o` скомпилированы без исполняемого стека
      - лучше всегда проверять все executables и libraries:
        ```
        # Не должно быть E (или X) в permissions
        $ readelf -lW myprog | grep GNU_STACK
        ...
          GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                         0x0000000000000000 0x0000000000000000  RW     0x10
        ...
        ```
      - если подгружается (через `dlopen`) проблемная библиотека,
        то до [недавнего времени](https://sourceware.org/bugzilla/show_bug.cgi?id=32653)
        она делала стек исполняемым
- расширения:
  * запрет исполнения не только для стека, но и для любых writable-сегментов
    + heap, static data
    + общее название идеи: W^X
  * раньше был PaX патч для `-Wl,noexecheap` (`pt-pax-flags.patch`),
    но динамическая память в Glibc и так noexec с доисторических времён
- оверхед отсутствует
- сравнение с безопасными языками:
  * в Rust стек [всегда неисполняемый](https://doc.rust-lang.org/rustc/exploit-mitigations.html#non-executable-memory-regions)
- как включить:
  * обычное использование
    + обычно компилятор просто сообщает линкеру о noexecstack с помощью
      ```
      .section .note.GNU-stack,"",@progbits
      ```
    + линкер включит noexecstack если все объектные файлы это разрешают
    + execstack требуется для ассемблерных файлов (в некоторых просто забыли указать
      директиву) и для указателей на GNU nested functions
      ([раньше](https://sourceware.org/bugzilla/show_bug.cgi?id=27220) использовались в Glibc)
      - отметим что важно именно взятие указателя от nested function
  * если линкер не справился то можно воспользоваться
    + опцией `-Wl,-z,noexecstack` в GCC/Clang, `/NXCOMPAT` в Visual Studio
    + отключить execstack в готовой программе с помощью утилиты `execstack(8)`
- использование в реальных проектах
  * все современные дистро используют noexecstack по умолчанию в GCC и Clang (из-за настроек компилятора)
    + проверено вручную для Ubuntu, Fedora, Debian, Android
    + на моей Debian 12 execstack включён только у `/usr/bin/vkd3d-compiler`,
      а на Debian 11 у программ из dpkg-query (`/usr/bin/lksh`, etc.):
      - `for f in /usr/bin/* /usr/sbin/*; do echo $f; readelf -l $f | grep -A2 GNU_STACK; done`

## ASLR (и -fPIE)

- суть проверки:
  * случайное расположение частей программы в адресном пространстве
    + стек, куча, код и данные приложения и библиотек
    + достигается рандомизацией результатов `mmap` в ядре ОС
  * динамические библиотеки уже поддерживают загрузку по произвольному адресу
    + т.н. position-independent code (опция `-fPIC`)
    + инструкции не используют абсолютные адреса
  * мы можем собрать в таком режиме и основное приложение ("full ASLR")
    + `-fPIE` = `-fPIC` + доп. оптимизации (связанные с невозможностью runtime interposition)
- пример ошибки
  * классическая атака Stack Smashing приведена [здесь](exploits/stack-smash)
  * при использовании ASLR стабильно получаем
    ```
    Segmentation fault (core dumped)
    ```
- история:
  * появление PaX patch для ядра Linux в 2001
  * в OpenBSD включили ASLR по дефолту в 2003
  * в Linux включили ASLR по дефолту в 2005
  * в Windows включили ASLR по дефолту в Vista (2007)
    + из-за архитектуры Windows DLL оверхед ASLR для 32-битных систем намного выше
- целевые уязвимости и распространённость
  * техника сильно снижает риски buffer overflow атак например return-to-libc и ROP
  * см. статистику выше
- эквивалентные отладочные проверки:
  * Asan (и до некоторой степени Valgrind, за исключением stack overflow) обнаруживают причину подобных ошибок (buffer overflow)
- проблемы:
  * рандомизируется только базовый адрес mmap
    * хакер знает относительные смещения кода, глобальных переменных, таблиц GOT/PLT программы и библиотек
    * если сливается адрес хотя бы одной сущности => хакер знает смещение всех остальных
      + https://www.openwall.com/lists/oss-security/2018/02/27/5
    * см. про защиту GOT ниже
  * защита уязвима к info leakage
    + например [format string attach](https://en.m.wikipedia.org/wiki/Uncontrolled_format_string)
  * недостаточная рандомизация (не все биты адреса одинаково случайны, относительный порядок библиотек и программы неслучаен)
    + например в 32-битных Windows [рандомизировалось только 8 (!) битов адреса загрузки](https://cloud.google.com/blog/topics/threat-intelligence/six-facts-about-address-space-layout-randomization-on-windows/)
      - так же в [32-битном Android](https://googleprojectzero.blogspot.com/2015/09/stagefrightened.html)
    + https://arxiv.org/abs/2408.15107
    + в Windows рандомизация каждого приложения делается однократно при его первой загрузке (для ускорения)
      - также одна и та же библиотека может грузиться по одному адресу в разных приложениях (для ускорения)
      - помогает только регулярный ребут сервера
    + даже в Linux рандомизация делается однократно при старте сервиса => уязвима к brute force (особенно на 32-битных платформах)
      - требуется регулярный рестарт сервисов
    + использование `fork` компрометирует ASLR т.к. ребёнок знает секрет (ASLR и кстати canary)
      - Android использует Zygote
  * ASLR убила подход предлинковки библиотек (Prelink), использовавшийся для ускорения загрузки
- расширения:
  * некоторые коммерческие тулчейны также динамически переупорядочивают сегменты в рантайме или линк-тайме (Safe Compiler, Moving Target Defense, Multicompiler)
- оверхед:
  * нет оверхеда при замерах на Clang
- сравнение с безопасными языками:
  * Rust [также собирается с `-fPIE`](https://doc.rust-lang.org/rustc/exploit-mitigations.html#position-independent-executable)
- как включить:
  * флаги `-fPIE -pie` (GCC, Clang), `/DYNAMICBASE` (Visual Studio)
  * включена по умолчанию в GCC/Clang в Ubuntu, Debian и Android
    + можно отключить флагом `-no-pie`
  * не включена по умолчанию в компиляторах Fedora
    + можно включить флагами `-fPIE -pie`
- ссылки на статьи:
  * [проблемы ASLR в Windows](https://cloud.google.com/blog/topics/threat-intelligence/six-facts-about-address-space-layout-randomization-on-windows/)
- использование в реальных проектах
  * пакеты Fedora дефолтно собираются с `-fPIE` (проверено в `redhat-rpm-config`)
  * пакеты Ubuntu и Debian дефолтно собираются с `-fPIE` (из-за дефолтных опций компилятора)
    + но например python3.11 в Debian не использует PIE (https://packages.debian.org/bookworm/python3.11-minimal
      - видимо изначально была причина в накладных расходах на i386 (https://bugs.launchpad.net/ubuntu/+source/python2.7/+bug/1452115)
  * много программ на Debian собраны без `-fPIE` (намного меньше на Ubuntu)
    + `for f in /usr/bin/* /usr/sbin/*; do if checksec --file=$f | grep -q 'No PIE'; then echo $f; fi; done`
    + в том числе `/usr/bin/pytho3` :(
  * браузеры Firefox и Chrome собраны с PIE

## Stack Protector

- рядом с return address на стеке размещается специальное случайное число ("канарейка", stack cookie)
  * переполнение буфера это memcpy, поэтому он не может изменить RA, не изменив канарейку (а её значение неизвестно)
  * также переупорядочивает переменные: скаляры кладутся ниже по стеку чем массивы
    + чтобы при переполнении массива нельзя было модифицировать флаги и т.п.
  * один из байтов канарейки всегда нулевой (чтобы остановить строковый buffer overflow)
- пример ошибки:
  * классическая атака Stack Smashing приведена [здесь](exploits/stack-smash)
  * при использовании Stack Protector стабильно получаем
    ```
    *** stack smashing detected ***: terminated
    Aborted (core dumped)
    ```
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
- целевые уязвимости и распространённость:
  * позволяет обнаруживать переполнение буфера перед return и соответственно ломает return-to-libc и ROP
  * см. статистику выше
- расширения:
  * аналоги канареек используются в некоторых аллокаторах для обнаружения overflow
- эквивалентные отладочные проверки: Asan (Valgrind не умеет находить stack overflow)
- оверхед
  * существенные накладные расходы:
    + загрузка значения канарейки
    + сохранение на стек
    + чтение и проверка перед return
  * известные результаты:
    + [`-fstack-protector-all` 0-9%](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43809.pdf)
    + [`-fstack-protector-strong` no overhead](https://zatoichi-engineer.github.io/2017/10/04/stack-smashing-protection.html)
  * 2% оверхед на Clang (67 сек. -> 68.5 сек. на CGBuiltin.cpp)
- проблемы
  * false positives: отсутствуют
  * false negatives:
    + уязвима к info leakage (если канарейка утекла, то защита неэффективна)
    + если канарейка хранится в том же сегменте что и стек, хакер может переписать и её
    + не защищает от переписывания указателей на функции на стеке
    + не защищает от перезаписи адреса возврата без overflow
- сравнение с безопасными языками
  * [Rust](https://doc.rust-lang.org/rustc/exploit-mitigations.html#stack-smashing-protection):
      + вообще коду на Rust эта опция не требуется, но она полезна в случае вызова внешних библиотек
      + есть опция для включения (`-Z stack-protector`), для обнаружения проблем с C частях программы,
        но по дефолту [отключена](https://github.com/rust-lang/compiler-team/issues/841)
- кaк включить:
  * флаг `-fstack-protector-strong` (GCC, Clang), `/GS` (Visual Studio)
  * включена по умолчанию в Ubuntu GCC и больше нигде (не в Debian, Fedora, Android)
- ссылки на статьи:
  * https://wiki.osdev.org/Stack_Smashing_Protector
  * https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard
- использование в реальных проектах
  * в Fedora пакеты дефолтно собираются с `-fstack-protector-strong` (проверено в `redhat-rpm-config`)
  * в Ubuntu пакеты дефолтно собираются с `-fstack-protector-strong` (из-за настроек компилятора)
  * в Debian пакеты дефолтно собираются с `-fstack-protector-strong` (проверено в `dpkg/scripts/Dpkg/Vendor/Debian.pm`)
    + вообще всего 85% пакетов Debian 10 использовали Stack Protector (https://arxiv.org/abs/2203.06834)
  * в Chrome по дефолту включён более слабый вариант `-fstack-protector` (https://chromium.googlesource.com/chromium/src/+/c53163760d24e2f40c0365a6224ec653cf501b81/build/config/compiler/BUILD.gn#409)
  * включён в релизной сборке Firefox (https://bugzilla.mozilla.org/show_bug.cgi?id=1503589)

## Разделение стеков

- aka SafeStack, aka backward-edge CFI, aka ShadowStack
  * отличие Shadow от Safe - в Shadow на втором стеке хранятся только return addresses,
    а в Safe тоже и безопасные локальные переменные и спиллы
- суть проверки:
  * основная проблема stack buffer overflow -
    адрес возврата хранится вместе с локальными массивами
  * мы можем разделить стек на две несвязные части:
    + адрес возврата (и возможно скалярные переменные, адрес которых не берётся)
    + все остальные
  * по сути это доп. улучшение StackProtector
  * совместима со StackProtector (он по прежнему применяется для unsafe stack для обнаружения overflow)
  * полная защита от stack buffer overflow + дополнительная рандомизация
    для критических данных
- пример ошибки:
  * тот же что для Stack Protector
- целевые уязвимости и распространённость
  * позволяет обнаруживать переполнение буфера перед return и соответственно ломает return-to-libc и ROP
  * в отличие от Stack Protector также защищает от атак на указатели на функции на стеке
  * см. статистику выше
- история:
  * множество различных решений, первое кажется StackShield (~2000)
- возможные расширения: N/A
- эквивалентные отладочные проверки: Asan
- оверхед:
  * [0.1% SafeStack](https://clang.llvm.org/docs/SafeStack.html)
  * 3% на Clang (69 сек. -> 71 сек. на CGBuiltin.cpp)
- проблемы:
  * false positives: неизвестны
  * false negatives:
  * в `-fsanitize=safe-stack` нет поддержки проверок в динамических библиотеках
    + их можно использовать, но они не будут использовать ShadowStack
    + возможно [поддержать их несложно](https://github.com/ossf/wg-best-practices-os-developers/issues/267#issuecomment-1835359166)
  * ShadowCallStack: только AArch64 и RISCV
- сравнение с безопасными языками
  * Rust [использует shadow stacks в найтли-сборке](https://doc.rust-lang.org/rustc/exploit-mitigations.html#backward-edge-control-flow-protection)
    + опции `-Z sanitizer=shadow-call-stack` или `-Z sanitizer=safestack`
- как включить:
  * несколько реализаций:
    + SafeStack (`-fsanitize=safe-stack`) - [не меняет ABI](https://fuchsia.dev/fuchsia-src/concepts/kernel/safestack#interoperation_and_abi_effects)
    + ShadowStack - чисто аппаратная реализация (атрибут у бинарного файла), включается по `-fcf-protection` (`-mshstk` не нужен и не входит в Intel CET `-fcf-protection`)
      - https://news.ycombinator.com/item?id=26061230
    + ShadowCallStack (`-fsanitize=shadow-call-stack` в GCC/Clang) - [не меняет ABI](https://fuchsia.dev/fuchsia-src/concepts/kernel/shadow_call_stack#interoperation_and_abi_effects)
      - AArch64-only
- ссылка на статью:
  * https://blog.includesecurity.com/2015/11/strengths-and-weaknesses-of-llvms-safestack-buffer-overflow-protection/
- использование в реальных проектах:
  * не включён по умолчанию в дистрах (проверено по билдскриптам, даже не поддержан в текущей версии GCC в них)
  * не включён в Chrome и Firefox
  * пока [не поддержан](https://github.com/slimm609/checksec/issues/301)
    в checksec (можно просто искать публичный символ `__safestack_init`)

## Stack clashing (aka stack probes)

- различные стеки и куча отделены друга от друга guard pages
  * незамапленными страницы, обращение к которым вызовет SEGV
  * ожидается что программа обратится к адреса на странице
    при создании стекового фрейма и исчерпание стека
    (stack overflow, не stack buffer overflow) будет обнаружено
  * но что если на фрейме дежит очень большой (>4096 байтов) массив и
    мы как бы перепрыгиваем guard page ?
  * идея пройти по всему фрейму с шагом 4096 перед началом работы,
    чтобы гарантированно спровоцировать SEGV
- TODO: пример (optional)
- история:
  * guard page в Linux был [внедрён в 2010](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2240)
  * [серия статей Qualys](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt) с ~10 proof of concept атаками (2017)
    + также https://www.openwall.com/lists/oss-security/2021/07/20/2
- целевые уязвимости и распространённость:
  * выделенной CWE для таких уязвимостей нет и непонятно как их искать
- возможные расширения: N/A
- эквивалентные отладочные проверки: не существует
- оверхед
  * [нет регрессий на Firefox](https://blog.llvm.org/posts/2021-01-05-stack-clash-protection/)
  * нет оверхеда на Clang
- проблемы:
  * false positives: неизвестны
  * false negatives: неизвестны
- сравнение с безопасными языками
  * в Rust stack probing [включён по умолчанию](https://doc.rust-lang.org/rustc/exploit-mitigations.html#stack-clashing-protection)
   (по крайней мере на x86)
- как включить
  * `-fstack-clash-protection` (ещё есть устаревший и неиспользуемый `-fstack-check`)
  * включены по умолчанию в Ubuntu GCC и больше нигде
- ссылки на статьи:
  * https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background
  * https://developers.redhat.com/blog/2019/04/30/stack-clash-mitigation-in-gcc-why-fstack-check-is-not-the-answer
  * https://developers.redhat.com/blog/2020/05/22/stack-clash-mitigation-in-gcc-part-3
- использование в реальных проектах
  * пакеты Fedora дефолтно собираются с `-fstack-clash-protection` на x86 и amd64
  * пакеты Ubuntu дефолтно собираются с `-fstack-clash-protection` (из-за настроек компилятора)
  * пакеты Debian 12 дефолтно нет (проверено в `dpkg_1.21`),
    но [будут включены в след. версии](https://github.com/jvoisin/compiler-flags-distro/issues/12)
  * checksec сейчас [не обнаруживает stack clash](https://github.com/slimm609/checksec/issues/300)
    + пришлось написать [свой скрипт](scripts/has_stack_clash_protection.py)
    + на Ubuntu почти все программы защищены
    + на Debian нет, даже highly-exposed программы: bash, bzip2, curl, ffmpeg, perl, python, etc.
  * Firefox [использует](https://bugzilla.mozilla.org/show_bug.cgi?id=1852202) `-fstack-clash-protection`
    + Chrome нет

## Фортификация (`_FORTIFY_SOURCE`)

- суть проверки:
  * фортификация добавляет проверки диапазонов в функции стандартной библиотеки
    (там где это возможно):
  * например в стандартных хедере Glibc можно увидеть что-то типа
    ```
    #if _FORTIFY_SOURCE > 0
    __attribute__((always_inline, __nothrow__, leaf)) void *
    memset (void *__dest, int __ch, size_t __len)
    {
       return __builtin___memset_chk (__dest, __ch, __len,
                                      __glibc_objsize0 (__dest));
    }
    #endif
    ```
  * в этом коде функция `memset_chk` определена в стандартной библиотеке
    и содержит проверку диапазона
  * интересный момент с макросом `__glibc_objsize0`: он определяется в два разных
    интринсика в зависимости от агрессивности проверок:
    + `_FORTIFY_SOURCE=2`: `__builtin_object_size` - вернёт константный размер объекта,
      если он известен (например для локальных массивов на стеке), иначе `SIZE_MAX`
    + `_FORTIFY_SOURCE=3`: `__builtin_dynamic_object_size` - делает простой
      статический анализ кода с целью определения размер для переменных буферов;
      например позволяет проверить диапазон для
      ```
      void *copy_obj (const void *src, size_t alloc, size_t copysize)
      {
        void *obj = malloc (alloc);
        memcpy (obj, src, copysize);
        return obj;
      }
      ```
  * как можно видеть реализация проверки требует совместной работы
    библиотеки (подмена стандартной функции на chk-версию) и компилятора (вычисление доп. параметров)
  * конкретный список проверяемых функций можно уточнить в реализации библиотеки Glibc;
    как минимум:
    + printf and friends - %n допускается только в readonly-строках (проверяется по `/proc/self/maps`)
    + string.h APIs (`memcpy`, `memset`, `strcpy`, `strcat`, `bzero`, `bcopy`, etc.) - проверки диапазона
    + unistd.h APIs (`read`, `pread`, `readlink`, etc.) - проверки диапазона
    + всего ~80 штук
- пример ошибки
  ```
  $ cat repro.c
  include <stdlib.h>
  #include <string.h>

  unsigned n = 4096;

  int main() {
    char *a = malloc(1);

    memset(a, 0, n);
    asm("" :: "r"(&a) : "memory");

    a = malloc(200);
    asm("" :: "r"(&a) : "memory");

    return 0;
  }

  # _FORTIFY_SOURCE=3
  $ gcc tmp5.c -O2 && ./a.out 
  *** buffer overflow detected ***: terminated
  Aborted (core dumped)

  # No _FORTIFY_SOURCE
  $ gcc -U_FORTIFY_SOURCE tmp5.c -O2 && ./a.out 
  Fatal glibc error: malloc.c:2599 (sysmalloc): assertion failed: (old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)
  Aborted (core dumped)
  ```
- история:
  * появились в Glibc 2.3.4 (2004)
  * нет аналога в Visual Studio
- целевые уязвимости:
  * любые buffer overflow (stack, heap)
  * см. статистику выше
- возможные расширения:
  * проверки в STL (см. ниже)
  * `-fsanitize=bounds`
    + проверки скалярных обращений к массивам констаного размера и VLA (аналог `_FORTIFY_SOURCE=2`)
    + нет оверхеда при компиляции CGBuiltin.cpp (68 сек.)
- эквивалентные отладочные проверки:
  * аналогичные проверки, но намного более эффективные и медленные, делают Asan и Valgrind
  * важно отметить что все санитары [не умеют анализировать `XXX_chk`-функции](https://github.com/google/sanitizers/issues/247)
    + из-за этого использовать их с `_FORTIFY_SOURCE` нельзя - можно пропустить баги в Asan или поймать false positives в Msan
    + из-за того что `_FORTIFY_SOURCE` включён по умолчанию его надо явно отключать в санитарных сборках:
      - `-U_FORTIFY_SOURCE` или `-D_FORTIFY_SOURCE=0`
    + на самом деле GCC (не Clang) вставляет доп. минимальную инструментацию в месте вызова
      для `memcpy_chk`, `memmove_chk`, `memset_chk`, но этого мало
    + [пытались](https://patchwork.ozlabs.org/project/glibc/patch/57CDAB08.8060601@samsung.com/) поправить в Glibc (безуспешно)
- оверхед:
  * [`_FORTIFY_SOURCE=2` gives 3% ffmpeg overhead](https://zatoichi-engineer.github.io/2017/10/06/fortify-source.html)
  * 2% на Clang (67 сек. -> 68.5 сек. на CGBuiltin.cpp, `-D_FORTIFY_SOURCE=3`)
  * без изменений на Clang (67 сек. на CGBuiltin.cpp, `-D_FORTIFY_SOURCE=2`)
- проблемы:
  * false positives:
    + ломает Msan: https://patchwork.ozlabs.org/project/glibc/patch/57CDAB08.8060601@samsung.com/
  * false negatives
    + поддержана только в Glibc и Bionic (не в musl)
      - standalone реализация: https://git.2f30.org/fortify-headers/files.html
    + работает только в `-O` режиме
    + работает только если подключены стандартные .h файлы (нет implicit declarations)
    + компилятор далеко не всегда может вывести допустимый размер указателя из контекста
      - ограничен рамками функции
  * поддержка на разных платформах
- сравнение с безопасными языками
  * Rust включает обязательные (и неотключаемые) проверки диапазанов
- как включить:
  * для явного включения используется `-D_FORTIFY_SOURCE=2` или `-D_FORTIFY_SOURCE=3`
    + до тех пор пока не появится `-D_FORTIFY_SOURCE=4` :)
  * standalone реализация: https://git.2f30.org/fortify-headers/files.html
  * проверка в дистре:
  ```
  $ gcc -x c /dev/null -O2 -E -dM | grep FORTIFY
  ```
  * Debian GCC: не включён по умолчанию в компиляторе
  * Fedora GCC: не включён по умолчанию в компиляторе
  * Ubuntu GCC: `-D_FORTIFY_SOURCE=3` по умолчанию в компиляторе
  * Clang: не включён по умолчанию нигде
- ссылки на статьи:
  * https://www.redhat.com/en/blog/security-technologies-fortifysource
  * https://maskray.me/blog/2022-11-06-fortify-source
- использование в реальных проектах
  * Debian (и Ubuntu): пакеты дефолтно собираются с `-D_FORTIFY_SOURCE=2` (проверено в `dpkg`)
  * Fedora: пакеты с 2023 дефолтно собираются с `-D_FORTIFY_SOURCE=3` (проверено в `redhat-rpm-config`)
  * Firefox и Chrome собраны с `-D_FORTIFY_SOURCE=2`

## Проверки STL

- aka "Hardened libc++"
- суть проверки:
  * зависят от компилятора и уровня проверки
  * всегда включают проверки индексов в `std::vector`, `std::deque`, `std::string`
    + а также `front`, `back`, etc.
  * GCC-specific:
    + проверки на `NULL` в умных указателях
    + проверки корректности параметров мат. функций и распределений
    + множество других мелких проверок типа `abs(INT_MIN)` в `std::gcd` и `std::lcm`
    + реализованы через макросы типа `__glibcxx_assert` в шаблонных реализациях
  * LLVM:
    + проверки на Strict Weak Ordering компараторов
      - см. доклад
    + множество других мелких проверок типа `abs(INT_MIN)` в `std::gcd` и `std::lcm`
  * Visual Studio:
    + также "checked iterators"
      - точно проверки не указны
    + [планируется удалить](https://www.reddit.com/r/cpp/comments/1hzj1if/comment/m6spu55),
      из-за [слишком большого оверхеда](https://www.reddit.com/r/cpp/comments/1hzj1if/comment/m6spg8v)
- пример ошибки
  ```
  $ cat repro.cc
  #include <stdio.h>
  #include <vector>

  int main() {
    std::vector<int> v;
    asm("" :: "r"(&v) : "memory");
    return v[4096];
   }

  $ g++ tmp.cc
  $ ./a.out
  Segmentation fault

  $ g++ -D_GLIBCXX_ASSERTIONS tmp.cc
  $ ./a.out
  /usr/include/c++/12/bits/stl_vector.h:1123: std::vector<_Tp, _Alloc>::reference std::vector<_Tp, _Alloc>::operator[](size_type) [with _Tp = int; _Alloc = std::allocator<int>; reference = int&; size_type = long unsigned int]: Assertion '__n < this->size()' failed.
  Aborted
  ```
- целевые уязвимости и распространённость:
  * индексные проверки предотвращают buffer overflow (см. статистику выше)
  * остальных проверок так много что трудно идентифицировать конкретные CVE
- история:
  * GCC debug containers (начало 2000-х)
  * опция `_GLIBCXX_ASSERTIONS` для hardening (2015, commit 2f1e8e7c)
  * libc++ и Safe Buffers proposal (2022)
  * далее видимо STL hardening станет составной частью C++ профилей
- возможные расширения:
  * скорее всего эти проверки станут частью Стандарта C++ (через механизм профилей)
    + инструменты для миграции уже есть ([Safe Buffers](https://discourse.llvm.org/t/rfc-c-buffer-hardening/65734))
    + caveat: [Updated Field Experience With Annex K — Bounds Checking Interfaces](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1969.htm (2015))
  * компиляторы поддерживают также ABI-breaking флаги, которые намного сильнее замедляют рантайм
  * рекомендуется включать их в QA-сборках
  * GCC: `-D_GLIBCXX_DEBUG` (надмножество `_GLIBCXX_ASSERTIONS`, несовместимо по ABI => требуется перекомпиляция C++-зависимостей)
  * Clang: [доп. макросы](https://libcxx.llvm.org/Hardening.html#abi) например для проверок итераторов (`_LIBCPP_ABI_BOUNDED_ITERATORS`, etc.)
  * Visual Studio: `/D_ITERATOR_DEBUG_LEVEL=1` (говорят может менять ABI,
    т.е. потребуется пересборка всех зависимостей,
    но в [коде](https://github.com/microsoft/STL) этого не видно)
- эквивалентные отладочные проверки:
  * Asan (и до некоторой степени Valgrind) обнаруживают причины подобных ошибок (buffer overflow)
- оверхед
  * [0.3% in Google server systems](https://security.googleblog.com/2024/11/retrofitting-spatial-safety-to-hundreds.html)
    + важно: [требуется поддержка ThinLTO и PGO](https://www.reddit.com/r/cpp/comments/1hzj1if/comment/m6vpzh4)
      иначе [можно ожидать 4x](https://bughunters.google.com/blog/6368559657254912/llvm-s-rfc-c-buffer-hardening-at-google)
  * 3.5% на Clang (67 сек. -> 69.5 сек. на CGBuiltin.cpp)
- проблемы:
  * false positives: неизвестны
  * false negatives:
    + покрывает только подмножество ошибок (некорректные индексы, только STL)
    + некоторые ошибки обнаруживать слишком дорого (например ошибки в итераторах)
- сравнение с безопасными языками
  * в Rust аналогичные проверки делаются всегда
- как включить:
  * `-D_GLIBCXX_ASSERTIONS` (libstdc++, дефолт в GCC и Clang), `-D_LIBCPP_HARDENING_MODE=...` (libc++, включается в Clang по `-stdlib=libc++`), `-D_ITERATOR_DEBUG_LEVEL=1` (Visual Studio)
  * по умолчанию ни включена ни в одном дистре
- TODO: ссылка на хорошую статью
- использование в реальных проектах:
  * [Google: Chrome and server systems](https://security.googleblog.com/2024/11/retrofitting-spatial-safety-to-hundreds.html)
  * [Google Andromeda <1% with FDO and 2.5% without](https://bughunters.google.com/blog/6368559657254912/llvm-s-rfc-c-buffer-hardening-at-google)
  * включена для пакетов Fedora, не включена для пакетов Debian и Ubuntu
    + https://bugs.launchpad.net/ubuntu/+source/gcc-12/+bug/2016042
  * не включены в Firefox, в Chrome только `_GLIBCXX_ASSERTIONS`

## Усиленные аллокаторы

- суть проверки:
  * дополнительные меры в динамическом аллокаторе для затруднения атак на метаданные аллокатора
- примеры реализации:
  * [Scudo](https://llvm.org/docs/ScudoHardenedAllocator.html) (дефолтный аллокатор Android, [описание](https://www.usenix.org/system/files/woot24-mao.pdf?ref=blog.exploits.club))
    + чексуммы для обнаружения перезаписи метаданных
    + рандомизация адресов внутри блоков
    + отложенное переиспользование освобождённой памяти (quarantine)
    + mmap-only (нет `sbrk(2)`, для рандомизации)
  * hardened_malloc:
    + метаданные физически отделены от аллоцируемой памяти (нет "хедеров")
    + рандомизация адресов внутри блоков
    + отложенное переиспользование освобождённой памяти (quarantine)
    + зануление данных на `free` и проверка на `malloc`
    + канарейки
    + mmap-only (нет `sbrk(2)`, для рандомизации)
  * [malloc-ng](https://gist.github.com/MaskRay/ac54b26d72452ac77ac578f2e625369f) (musl allocator)
    + метаданные физически отделены от аллоцируемой памяти (нет "хедеров")
    + рандомизация адресов внутри блоков
    + канарейки
  * Glibc
    + pointer encryption - XOR всех указателей на функции с канарейкой
    + усиленные проверки heap consistency ([функция mcheck](https://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html))
- пример ошибки
  ```
  $ cat repro.c
  #include <string.h>
  #include <stdlib.h>

  void *a, *b;
  unsigned n = 4096;

  int main() {
    a = malloc(100);
    memset(a, 0xff, n);
    b = malloc(100);
  }

  $ gcc -O2 repro.c
  $ ./a.out
  malloc(): corrupted top size
  Aborted
  ```
  или
  ```
  $ cat repro.c
  #include <stdlib.h>

  void *a, *b;

  int main() {
    a = malloc(1);
    free(a);
    b = malloc(1);
    free(a);
    return 0;
  }

  $ gcc -O2 repro.c
  $ ./a.out
  $ LD_PRELOAD=$HOME/src/hardened_malloc/out/libhardened_malloc.so ./a.out
  fatal allocator error: double free (quarantine)
  Aborted
  ```
- TODO: история (optional)
- целевые уязвимости и распространённость:
  * heap overflow, use-after-free, double free, free of invalid address
  * статистика CVE/KEV приведена выше
- возможные расширения: неизвестны
- эквивалентные отладочные проверки: Asan, Valgrind, ElectricFence
- оверхед
  * [musl allocator 2-10x](https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance/)
    + это из-за [global lock](https://news.ycombinator.com/item?id=23081071), не имеет значения
  * hardened_malloc vs Glibc allocator: 9% на Clang (67 сек. -> 73 сек. на CGBuiltin.cpp)
- проблемы:
  * false positives: неизвестны
  * TODO: false negatives (искать "bypassing FEATURE")
  * атаки на Scudo: https://www.usenix.org/system/files/woot24-mao.pdf
- сравнение с безопасными языками
  * в Rust невозможны ошибки памяти
- как включить:
  * обычно достаточно `LD_PRELOAD=path/to/new/allocator.so`
  * проверки в Glibc включаются по `MALLOC_CHECK_=3` или `GLIBC_TUNABLES=glibc.malloc.check=3`
- ссылки на статьи:
  * https://www.l3harris.com/newsroom/editorial/2023/10/scudo-hardened-allocator-unofficial-internals-documentation
  * https://github.com/struct/isoalloc/blob/master/SECURITY_COMPARISON.MD
- использование в реальных проектах:
  * Android использует Scudo по дефолту, остальные дистры Glibc allocator
  * Chrome [использует](https://blog.chromium.org/2021/04/efficient-and-safe-allocations-everywhere.html)
    hardened-аллокатор PartitionAlloc
  * Firefox [использует](https://madaidans-insecurities.github.io/firefox-chromium.html#memory-allocator-hardening)
    не-hardened аллокатор
  * GrapheneOS использует hardned_malloc

## Защита таблиц диспетчеризации

- вызовы функции из динамических библиотек делаются через PLT stubs
  * даже если библиотека вызывает свои собственные функции (см. доклад про оптимизации)
  * PLT stubs читают и обновляют таблицу указателей на функции
  * таблицу приходится держать в writable-сегменте => у хакеров есть возможность её модифицировать
  * флаги линкера `-Wl,-z,now -Wl,-z,relro` (т.н. "Full RELRO") заставляют дин. загрузчик
    + инициализировать содержимое таблиц на старте программы (`-z,now`)
    + пометить сегмент readonly (`-z,relro`)
  * доп. преимущество - нет проблемы с отложенными ошибками ненайденных символов
- пример ошибки (Ubuntu 24.04, Debian 12):
  ```
  $ cat repro.c
  #include <stdio.h>

  void shellcode() {
    printf("You have beeen pwned%s\n", "");
  }

  extern void *_GLOBAL_OFFSET_TABLE_[];

  int main() {
    _GLOBAL_OFFSET_TABLE_[POS] = shellcode;
    printf("Hello world!\n");
    return 0;
  }

  $ for i in `seq 0 16`; do gcc -Wl,-z,norelro repro.c -DPOS=$i; ./a.out; i=$((i + 1)); done
  Segmentation fault
  Segmentation fault
  Segmentation fault
  You have beeen pwned
  Hello world!
  Hello world!
  Hello world!
  Hello world!
  ...
  ```
- история:
  * подход RELRO уже использовался ранее для однократно инициализируемых таблиц (vtables)
    + см. [статью Ian Lance Taylor](https://www.airs.com/blog/archives/189)
  * потребовалась лишь небольшая адаптация для GOT
- целевые уязвимости и распространённость: соответствующие CVE не найдены
  * более редкая атака чем buffer overflow, но вполне реальная:
    + смещение GOT/PLT известно
    + хакер с помощью ROP может поменять их и сделать return-to-plt
- эквивалентные отладочные проверки:
  * не существуют (ни Valgrind, ни санитары не защищают от перезаписи GOT)
- оверхед
  * замедляет только старт приложения
  * можно использовать с `-fno-plt` ([10% прирост перфа](https://patchwork.ozlabs.org/project/gcc/patch/alpine.LNX.2.11.1505061730460.22867@monopod.intra.ispras.ru/))
  * известные результаты не найдены
  * оверхед на Clang не обнаружен
- проблемы:
  * false positives: неизвестны
  * false negatives:
    + некоторые программы могут сломаться (если в них были отсутствующие символы, которые не вызывались)
    + пользовательские таблицы функций не защищены e.g. atexit handlers (важно ли это ?)
- сравнение с безопасными языками
  * Rust [использует](https://doc.rust-lang.org/rustc/exploit-mitigations.html#read-only-relocations-and-immediate-binding) Full RELRO
- как включить
  * указать опции линкера: `-Wl,-z,now -Wl,-z,relro`
    + можно просто `-z now -z relro`
  * поддержка в дистрибутивах и тулчейнах:
    + Debian: не включены по умолчанию ни в GCC, ни в Clang
    + Ubuntu: включены по умолчанию в GCC, но только `-z relro` в Clang (partial RELRO)
    + Fedora: не включены по умолчанию ни в GCC, ни в Clang
- ссылка на статью:
  * https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
- использование в реальных проектах
  * Debian: пакеты дефолтно [собираются с partial RELRO](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options)
    + проверено в `dpkg`
  * Fefora: пакеты дефолтно [собираются с full RELRO](https://fedoraproject.org/wiki/Security_Features_Matrix#Built_with_RELRO))
    + проверено в `redhat-rpm-config`
  * Ubuntu: пакеты дефолтно собираются с full RELRO (из-за настроек компилятора)
    + отключено в `dpkg` !
  * Firefox: дефолтно включён (https://github.com/mozilla-firefox/firefox/blob/9fb43aa7996146d3dc1bb3ab09f618c0b8b4bcef/build/moz.configure/flags.configure#L341)
  * Chrome: дефолтно включён (https://chromium.googlesource.com/chromium/src/+/c53163760d24e2f40c0365a6224ec653cf501b81/build/config/compiler/BUILD.gn#523)

## Уменьшение зависимостей

- суть техники:
  * часто программа линкует лишние библиотеки (например из-за устаревших билдскриптов)
  * от них можно избавиться без ручной модификации Makefiles с помощью флагов `-Wl,--as-needed`
    + [иногда](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html#allow-linker-to-omit-libraries-specified-on-the-command-line-to-link-against-if-they-are-not-used)
      также рекомендуют флаг `-Wl,--no-copy-dt-needed-entries`, но во-первых он не влияет на безопасность,
      а во-вторых и так включён по умолчанию в современных линкерах
  * обычно эти опции используют только для ускорения стартапа, но у них есть вторичный эффект:
    + уменьшается число доступных хакеру библиотек (для поиска гаджетов)
  * могут быть полезны против всех stack overflow атак, полагающихся на ROP
- история:
  * появились в GNU ld в 2004 как оптимизация для динамических библиотек
  * OpenSSF стала рекомендовать её в [2024](https://github.com/ossf/wg-best-practices-os-developers/issues/510)
- целевые уязвимости и распространённость:
  * уменьшает вероятность найти ROP gadgets для stack overflow атак
  * см. статистику выше
- эквивалентные отладочные проверки: те же что у неисполняемого стека
- расширения:
  * ленивое связывание библиотек (см. доклад Грибова)
- оверхед: отсутствует (наоборот, стартап может ускориться)
- проблемы:
  * false positive: могут сломаться некоторые программы
    + например которые использовали символы отброшенных либ с помощью `dlsym`
  * false negative: линкер делает `--as-needed` после `--gc-sections`
    поэтому [может оставить некоторые ненужные библиотеки](https://sourceware.org/bugzilla/show_bug.cgi?id=24836):
    ```
    $ cat repro.c
    #include <math.h>

    // Эта функция будет выброшена
    float foo(float x) { return sinf(x); }

    int main() { return 0; }

    # Дефолтно требуется линковка с libm
    $ gcc repro.c -O2
    /usr/bin/ld: /tmp/ccmERumv.o: in function `foo':
    tmp8.c:(.text+0x1): undefined reference to `sinf'
    collect2: error: ld returned 1 exit status
    $ gcc repro.c -O2 -lm
    $ readelf -sW a.out | grep foo
        29: 0000000000001170     5 FUNC    GLOBAL DEFAULT   15 foo
    $ ldd a.out
            linux-vdso.so.1 (0x00007fff45686000)
            libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007ff3af5c7000)
            libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff3af3e6000)
            /lib64/ld-linux-x86-64.so.2 (0x00007ff3af6c3000)

    # С --gc-sections функция foo была выброшена,
    # но линкер оставил зависимость от libm
    $ gcc repro.c -O2 -Wl,--as-needed -ffunction-sections -Wl,--gc-sections -lm
    $ readelf -sW a.out | grep foo
    $ ldd a.out
            linux-vdso.so.1 (0x00007fff1ad1e000)
            libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fe2f1cbb000)
            ...
    ```
- сравнение с безопасными языками
  * Rust компилируется только с `--as-needed` (как и GCC/Clang)
- как включить
  * опция линкера `-Wl,--as-needed`
  * включена по умолчанию в GCC в Debian и Ubuntu, но не в Fedora
  * не включена по умолчанию в Clang нигде
- ссылка на хорошую статью: https://wiki.gentoo.org/wiki/Project:Quality_Assurance/As-needed
- использование в реальных проектах:
  * пакеты в Fedora дефолтно собираются с `--as-needed` (а также Debian и Ubuntu)

## Автоматическая инициализация

- инициализация всех локальных переменных (нулями для hardening, случайными значениями для debug)
- пример ошибки:
  ```
  // Компилятор может скомпилировать эту функцию,
  // а также любую функцию, которая её гарантированно вызывает,
  // в nop или halt
  int foo() {
    int x;
    if (x)
      bar();
    else
      bro();
  }
  ```
- история
  * предложения высказывались с незапамятных времён (например с [2014 года](https://gcc.gnu.org/legacy-ml/gcc-patches/2014-06/msg00615.html))
  * [InitAll](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_09_CppCon/CppCon2019%20-%20Killing%20Uninitialized%20Memory.pdf) в Windows появился в 2019
  * GCC в [2021](https://gcc.gnu.org/pipermail/gcc-patches/2021-February/565514.html)
- расширения:
  * неинициализированные переменные и C++26 (@Роман):
    + использование неинициализированной переменной станет erroneous behavior:
      - не UB
      - компилятор должен либо выдать проверку, либо инициализировать
      - компилятор не сможет делать вышеуказанные проблемные оптимизации
        * их можно будет включить явно с помощью атрибута `[[indeterminate]]`
    + [P2795](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2795r3.html)
    + [P2723](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2723r1.html)
- эквивалентные отладочные проверки: Msan, Valgrind, [DirtyFrame](https://github.com/yugr/DirtyFrame)
- целевые уязвимости и распространённость:
  * около 50 uninitialized variable CVE в 2024 (1% от buffer overflow CVE)
  * не найдено ни одного KEV
  * 10% CVE root cause в продуктах Microsoft в 2018 ([отсюда](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_09_CppCon/CppCon2019%20-%20Killing%20Uninitialized%20Memory.pdf))
  * [12% exploitable bugs on Android](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2723r1.html#real-world)
- оверхед:
  * [1% на Firefox](https://serge-sans-paille.github.io/pythran-stories/trivial-auto-var-init-experiments.html)
  * may take over 10% on hot paths:
    + [virtio](https://patchwork-proxy.ozlabs.org/project/qemu-devel/patch/20250604191843.399309-1-stefanha@redhat.com/)
    + [Chrome](https://issues.chromium.org/issues/40633061#comment142) (исправление заняло ~4 месяца)
  * [1-3% в среднем на Postgres (до 20% на некоторых кейсах)](https://bugs.launchpad.net/ubuntu/+source/dpkg/+bug/1972043/comments/11)
  * [<1% в Windows](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_09_CppCon/CppCon2019%20-%20Killing%20Uninitialized%20Memory.pdf)
  * 4.5% оверхед на Clang (67 сек. -> 70 сек. на CGBuiltin.cpp)
  * существенный оверхед если на hot path есть
    большой локальный массив (например для IO)
  * пример проблемы:
    ```
    while (std::getline(maps, line)) {
      char modulePath[PATH_MAX + 1] = "";
      // -ftrivial-auto-var-init вставит здесь memset...
      ret = sscanf(line.c_str(),
                   "%lx-%lx %6s %lx %*s %*x %" PATH_MAX_STRING(PATH_MAX)
                   "s\n",
                   &start, &end, perm, &offset, modulePath);
    }
    ```
- проблемы
  * false positives: неизвестны
  * false negatives:
    + ломает обнаружение багов в Valgrind и Msan
    + инициализация нулями не всегда даёт осмысленный результат (мы скорее скрываем проблему, а не фиксим)
      - в Linux 0 это например id суперпользователя
    + применяется только к локальным переменным (глобальные и так инициализируются, для кучи можно использовать Scudo hardened allocator)
- сравнение с безопасными языками
  * Rust заставляет программиста инициализировать переменные (или явно использовать враппер `MaybeUninit`)
    + также Swift, C#
  * Java заставляет программиста инициализировать локальные переменные (динамическая память гарантированно зануляется)
- как включить:
  * флаг `-ftrivial-auto-var-init=zero` (GCC, Clang), [скрытый](https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html) [флаг](https://msrc.microsoft.com/blog/2020/05/solving-uninitialized-stack-memory-on-windows/) `-initall` (Visual Studio)
    + можно использовать не только нули, но [считается](https://lists.llvm.org/pipermail/cfe-dev/2020-April/065221.html)
      что нулевая инициализация более безопасна
- использование в реальных проектах
  * не включён по умолчанию ни в одном дистро
    + [обсуждение в Ubuntu](https://bugs.launchpad.net/ubuntu/+source/dpkg/+bug/1972043)
  * [включён в Chrome](https://issues.chromium.org/issues/40633061)
    + исправление и отключение hot paths заняло ~4 месяца
  * [не включён в Firefox](https://serge-sans-paille.github.io/pythran-stories/trivial-auto-var-init-experiments.html)
  * [включён в Android user/kernel space](https://android-developers.googleblog.com/2020/06/system-hardening-in-android-11.html)
- статьи:
  * https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_09_CppCon/CppCon2019%20-%20Killing%20Uninitialized%20Memory.pdf

## Проверки целочисленного переполнения

- суть проверки:
  * существующие отладочные инструменты для проверки переполнения
    (UBsan и Isan) имеют достаточно низкий оверхед
  * их использование в проде затруднено, т.к. они используют
    большой рантайм, открывающий новые возможности для атаки
  * решение: использование "Ubsan minimal runtime"
    (немедленный аборт программы)
- пример ошибки:
  ```
  // Из OpenSSH 3.3
  nresp = packet_get_int();
  if (nresp > 0) {
    // Переполняем целое число до нуля здесь ...
    response = xmalloc(nresp*sizeof(char*));
    // ... и вызываем heap buffer overflow тут
    for (i = 0; i < nresp; i++)
      response[i] = packet_get_string(NULL);
  }
  ```
- целевые уязвимости и распространённость (анализ CVE/KVE):
  * все ошибки Integer Overflow (статистика приведена выше)
  * два канонических примера: инцидент с облучателем Therac-25 и катастрофа ракеты Ariane 5
- история:
  * опция `-ftrapv` появилась в [2000](https://gcc.gnu.org/legacy-ml/gcc-patches/2000-10/msg00607.html)
    + за фичей не следили и она быстро [протухла](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=35412)
  * работы John Regehr в [2010](https://blog.regehr.org/archives/1559)
  * UBsan в [2014](https://developers.redhat.com/blog/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan)
    + state-of-the-art
- возможные расширения
  * помимо UBsan рекомендуется включать Isan (надо будет отключить инструментацию в STL RNG,
    там ест intentional unsigned overflow)
  * `-ftrapv` неработоспособна
- эквивалентные отладочные проверки:
  * UBsan/Isan может использоваться и как отладочный инструмент
- оверхед:
  * [до 2x на SPEC](https://arxiv.org/pdf/1711.08108) - полный UBsan
  * 33% оверхед на Clang (69 сек. -> 92 сек. на CGBuiltin.cpp)
  * 3x оверхед на Clang полного UBsan
- проблемы
  - false positives:
    * Isan может выдавать ложные срабатывания
      (в частности нужен blacklist для кода в STL,
       полагающегося на переполнение, флаг `-fsanitize-ignorelist`)
  - false negatives:
    * UBsan несовместим с `-fno-strict-overflow` и `-fwrapv`
    * может не обнаруживать некоторые баги,
      которые успел "перехватить" оптимизатор (особенно под `-O2`):
      ```
      // Helge Penne, Secure development with C++ - Lessons and techniques
      #include <limits.h>

      int foo() {
        int x = INT_MAX;
        int y = x + 1;
        if (y > x)
          return 1;
        return 2;
      }
      ```
- сравнение с безопасными языками:
  * в Rust проверки признаны достаточно дорогоми и редкими,
    поэтому по умолчанию они отключены в release;
    более того, некоторые операции (например приведения типов)
    вообще не проверяются
  * в Swift проверки переполнения включены по умолчанию
- как включить
  * Clang: `-fsanitize=undefined -fsanitize-minimal-runtime` (рекомендую также добавлять `integer`)
  * GCC: `-fsanitize-trap=undefined` (`integer` не поддержан в GCC)
- ссылка на статью:
  * https://developers.redhat.com/blog/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan
- использование в реальных проектах
  * не используется в дистрах
  * не используется в Chrome и Firefox
  * используется во Android user- и kernel-space:
    + https://android-developers.googleblog.com/2020/06/system-hardening-in-android-11.html
    + ранее только в Android media stack:
      - https://android-developers.googleblog.com/2016/05/hardening-media-stack.html
      - https://android-developers.googleblog.com/2018/06/compiler-based-security-mitigations-in.html

## Отключение агрессивных оптимизаций

- некоторые компиляторы могут излишне агрессивно
  реагировать на код, содержащий неочевидные для программиста ошибки,
  и генерировать очень небезопасный ассемблер
  (в основном выбрасывать пользовательские проверки)
- Compiler Introduced Security Bugs
  * термин введён в статье "Silent Bugs Matter: A Study of Compiler-Introduced Security Bugs"
  * статья "Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior"
- для кода с повышенными требованиями безопасности рекомендуется
  отключать такие оптимизации
- пример из Linux kernel: компилятор удалил проверку на NULL:
  ```
  static void __devexit agnx_pci_remove (struct pci_dev *pdev)
  {
    struct ieee80211_hw *dev = pci_get_drvdata(pdev);
    struct agnx_priv *priv = dev->priv;

    if (!dev) return;

    ... do stuff using dev ...
  }
  ```
- Visual Studio [менее агрессивен](https://devblogs.microsoft.com/cppblog/new-code-optimizer/)
  чем GCC/Clang
- обычно отключают:
  * `-fno-delete-null-pointer-checks`, `-fno-strict-overflow`, `-fno-strict-aliasing` (GCC/Clang)
    + заметим что `-fno-strict-overflow` == `-fwrapv` + `-fwrapv-pointer`
  * [`d2SSAOptimizerUndefinedIntOverflow-`](https://devblogs.microsoft.com/cppblog/new-code-optimizer/) (Visual Studio)
- целевые уязвимости и распространённость:
  * CVE по этой фиче очень мало (например [CVE-2009-1897](https://nvd.nist.gov/vuln/detail/CVE-2009-1897)),
    но в статьях находят сотни CISB в open-source коде:
    + "Silent Bugs Matter: A Study of Compiler-Introduced Security Bugs"
    + "Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior"
- TODO: история (optional)
- возможные расширения:
  * иногда рекомендуют флаг `-fwrapv`, но он плохо поддерживается
    (баги [не фиксят десятилетиями](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=30484))
- эквивалентные отладочные проверки: UBsan/Isan (strict overflow), TySan (strict aliasing)
  * ссылка на Ромин доклад
- оверхед
  * известные результаты:
    + [3-10% performance loss due to `-fno-strict-aliasing`](https://docs.lib.purdue.edu/cgi/viewcontent.cgi?article=1124&context=ecetr) (очень старое исследование)
    + [слабое отрицательное влияние `-fno-strict-aliasing`](https://llvm.org/devmtg/2023-05/slides/Posters/05-Popescu-PerformanceImpactOfExploitingUndefinedBehavior.pdf)
  * 4.5% оверхед на Clang (67 сек. -> 70 сек. на CGBuiltin.cpp)
- сравнение с безопасными языками
  * Rust:
    + strict overflow всегда defined (паника или wrap around)
    + strict aliasing невозможен по правилам языка
    + нулевые указатели невозможны в safe-коде
- как включить:
  * флаги выключены по умолчанию во всех компиляторах и дистрибутивах
    + многие пакеты в дистрах собираются с `-fno-strict-aliasing`
      (т.к. правила алиасинга особенно легко нарушить)
- ссылки на статьи:
  * [обсуждение `-fwrapv` в Firefox](https://bugzilla.mozilla.org/show_bug.cgi?id=1031653)
  * [Security flaws caused by compiler optimizations](https://www.redhat.com/en/blog/security-flaws-caused-compiler-optimizations)
  * https://my.eng.utah.edu/~cs5785/slides-f10/Dangerous+Optimizations.pdf
  * статьи John Regehr: https://blog.regehr.org/archives/213 и https://blog.regehr.org/archives/1520
- использование в реальных проектах:
  * дефолтно не используются в дистрибутивах
  * все три [используются](https://chromium.googlesource.com/chromium/src/+/c53163760d24e2f40c0365a6224ec653cf501b81/build/config/compiler/BUILD.gn#289)
    в Chrome
  * в Firefox только `-fno-strict-aliasing` (https://issues.chromium.org/issues/40342348)
  * TODO: проверить сколько пакетов используют эти флаги (как ?)

## Control-flow integrity

- пример ошибки:
  ```
  $ cat repro.cc
  #include <stdio.h>

  struct A { virtual void foo() {} };
  struct B : A { void foo() override {} };

  struct Evil { virtual void foo() { printf("You have been pwned\n"); } };

  A *tmp = new B;

  int main() {
    A *a = new A;
    Evil *e = new Evil;
    asm("mov %1, %0" : "+r"(a) : "r"(e));
    a->foo();
  }

  # Подмена объекта
  $ clang++ repro.cc -O2
  $ ./a.out
  You have been pwned

  # CFI обнаруживает подмену
  $ clang++ -fsanitize=cfi -flto -fvisibility=hidden repro.cc -O2
  $ ./a.out
  Illegal instruction
  ```
- история:
  - generic-термин для любых нарушений исходного control-flow
  - впервые введён Abadi et al. в 2005 (https://mihaibudiu.github.io/work/ccs05.pdf)
  - в широком смысле Stack Protector и Shadow Stack - варианты CFI
  - два типа: forward-edge (проверка call/jump) и backward-edge (проверка ret)
  - много различных методик в статьях
  - обычно под CFI понимают современные методы: LLVM CFI, Intel CET и AArch64 CFI (PAC и BTI)
  - LLVM CFI (2015, Clang 3.7)
  - Microsoft Control Flow Guard, 2014 (https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
  - Intel CET, 2020 (спека 2016)
  - grsecurity RAP (https://grsecurity.net/rap_faq)
- LLVM CFI:
  * компиляторная инструментация
  * не поддержана в GCC
  * только forward-edge
  * проверка совпадения статического и динамического прототипа при вызове функции по указателю
  * поддерживает vtables и обычные указатели на функции
    + алгоритмы проверки для них сильно различаются
  * также может использоваться для доп. проверок (корректность C++ кастов и пр.)
- Аппаратная поддержка:
  * Intel CET и AArch64 CFI
  * поддержана в GCC и Clang
  * более грубые проверки чем LLVM CFI
  * Intel IBT:
    + помечаем возможные цели всех бранчей/вызовов/возвратов в программе спец. инструкцией-хинтом `endbr64`
    + TODO: есть ещё какие-то проверки в CET (e.g. `-mshstk`) ?
  * AArch64 CFI (PAC, BTI):
    + BTI - аналогичный функционал Intel CET BTI
    + PAC (Pointer Auth):
      - верхние биты адреса возврата используются для вычисления криптостойкой чексуммы
        (адрес возврата + адрес фрейма + секрет процесса)
      - проверяются перед `ret`
- целевые уязвимости и распространённость (анализ CVE/KVE):
  * дополнительная защита от любых ошибок памяти (overflow, heap errors, etc)
  * см. статистику выше
- эквивалентные отладочные проверки:
  * отсутствуют (Asan, UBsan и Valgrind не проверяют типы)
- оверхед
  * компиляция CGBuiltin.cpp компилятором Clang:
    + без изменений на `-fcf-protection` (67 сек.)
    + 6% на `-fsanitize-cfi` (63 сек. -> 67 сек.)
  * [<1% бенмарк Dromaeo](https://clang.llvm.org/docs/ControlFlowIntegrity.html)
  * [<1% Chrome](https://www.chromium.org/developers/testing/control-flow-integrity/)
  * [нет оверхеда на Android](https://source.android.com/docs/security/test/cfi)
  * [до 10% увеличение кода](https://www.chromium.org/developers/testing/control-flow-integrity/) (I$ misses)
- проблемы:
  * false positives:
    + большое количество софта надо дорабатывать для LLVM CFI (например падает Clang)
  * false negatives:
    + LLVM CFI: проверяются только несоответствия на уровне типов (хакер может вызвать неправильную функцию если типы совпадают)
    + CET: вообще не проверяет типы
    + не проверяются jump tables, сгенерированные для `switch`-конструкций (только в CET есть `-mcet-switch`, дефолтно выключен)
  * проблемы с интеграцией к LLVM CFI:
    + требует LTO
    + проблемы: немонолитные иерархии (вызовы между границами DSO)
      - нужна спец. опция и дополнительный оверхед
  * фрагментация: три несвязанных решения с разными, GCC не поддерживает LLVM CFI
- сравнение с безопасными языками
  * Rust поддерживает `-Zsanitizer=cfi` и `-Zcf-protection=full`, но они не включены по умолчанию
  * нужна только для unsafe и внешнего кода
  * TODO: посмотреть [tracking issue](https://github.com/rust-lang/rust/issues/89653)
- как включить
  * LLVM CFI:
    + не включена по умолчанию ни в GCC, ни в Clang на Ubuntu, Debian, Fedora
    + включается по `-fsanitize=cfi`, также требует `-flto=thin -fvisibility=hidden`
    + LTO для построения полного call graph программы, visibility для сокращения внешних вызовов
    + для библиотечных вызовов нужна `-fsanitize-cfi-cross-dso`
  * Intel CET:
    + включается по `-fcf-protection`
    + включена по умолчанию в GCC на [Ubuntu](https://wiki.ubuntu.com/ToolChain/CompilerFlags)
    + раньше ещё нужно было указывать флаги `-mcet`, `-mshstk` и `-mibt`,
      теперь [они не нужны](https://reviews.llvm.org/D46881)
  * Windows (Control Flow Guard): `/guard:cf` (to be replaced with Xtended Flow Guard)
  * AArch64 CFI: флаг `-mbranch-protection=standard`
    + [никто не знает](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1021292#84)
      почему это не сделано под `-fcf-protection` :(
- ссылки на статьи:
  * LLVM CFI: https://blog.trailofbits.com/2016/10/17/lets-talk-about-cfi-clang-edition/
  * AArch64 CFI: https://lists.debian.org/debian-dpkg/2022/05/msg00022.html
- использование в реальных проектах (дистрах, браузерах и т.д.)
  * включена по дефолту на Android
  * `-fsanitize=cfi` не включена в Ubuntu, Debian, Fedora
    + логично, ведь GCC её не поддерживает и она требует LTO
  * Intel CET и AArch64 BP дефолтно включены для пакетов в [Ubuntu](https://wiki.ubuntu.com/ToolChain/CompilerFlags)
    + проверено по `dpkg_1.22.6ubuntu6.2`
  * Intel CET и AArch64 BP дефолтно включены для пакетов в [Fedora](https://fedoraproject.org/wiki/Changes/HardeningFlags28)
    + проверено по `redhat-rpm-config`
  * Intel CET и AArch64 BP не включены для пакетов в Debian 12 (проверено в `dpkg_1.21.22`)
    + будут включeны в след. версиях
      (проверено по `dpkg` + [коммит](https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=8f5aca71c1435c9913d5562b8cae68b751dff663))
  * Chrome использует LLVM CFI на X86 и AArch64 CFI на AArch64 платформах
  * Firefox не использует никакие варианты CFI
  * checksec не обнаруживает
    + LLVM CFI (непонятно как это сделать)
    + Intel CET ([checksec #302](https://github.com/slimm609/checksec/issues/302))

## `-fhardened`

- зонтичная опция для наиболее важных hardened-оптимизаций
- включает [все опции, рекомендованные OpenSSF](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html)
- хороший дефолтный флаг, но пока реализован только в GCC
  * [Clang issue](https://github.com/llvm/llvm-project/issues/122687)
  * не используется ни в одном дистро
  * семантика может зависеть от версии компилятора
    + для GCC можно посмотреть функцию `print_help_hardened`, сейчас
      ```
      -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -ftrivial-auto-var-init=zero -fPIE -Wl,-z,now -Wl,-z,relro -fstack-protector-strong -fstack-clash-protection -fcf-protection=full
      ```
- аналогичную опцию для Rust [пока не добавили](https://github.com/rust-lang/rust/issues/15179)

## Опции для гарантированной очистки локальных данных

- Пароли и т.п.
- Не будем обсуждать подробно
- Опции GCC:
  * stack scrubbing - очистка стека при выходе из функции (`-fstrub`)
  * [`-fzero-call-used-regs`](https://www.semanticscholar.org/paper/Clean-the-Scratch-Registers%3A-A-Way-to-Mitigate-Rong-Xie/6f2ce4fd31baa0f6c02f9eb5c57b90d39fe5fa13) - очистка регистров при выходе из функции
- HW-атаки (Spectre, etc.)

## Безопасные языки (Rust)

- Все Rust CVE, связанные с ошибками памяти, вызваны ошибками в unsafe code (за исключением 1 бага в компиляторе)
  * [Memory-Safety Challenge Considered Solved? An In-Depth Study with All Rust CVEs](https://arxiv.org/pdf/2003.03296) (HUI XU et al., 2021)
- 20% крейтов содержат unsafe-код
  * [How Do Programmers Use Unsafe Rust?](https://dl.acm.org/doi/pdf/10.1145/3428204) (ASTRAUSKAS et al., 2020)
- 50% популярных крейтов содержат unsafe-код
  * [Is Rust Used Safely by Software Developers?](https://arxiv.org/pdf/2007.00752) (Evans et al., 2020)
- Свежая статья по unsafe Rust:
  * [Targeted Fuzzing for Unsafe Rust Code](https://arxiv.org/html/2505.02464v1)
- процентное соотношение unsafe-кода:
  * stdlib::core (294920bd) - 8.6% (5439/63041)
  * SpacetimeDB (69ec8033) - 2.1% (1904/90331)
  * bevy (de79d3f3) - 3.5% (10448/297552)
  * meilisearch (8a0bf24e) - 0% (219/90169)
  * nalgebra (db2d242d) - 4.4% (2066/46545)
  * oxipng (788997c4) - 0% (1/4383)
  * rav1e (6ee1f3a6) - 6.9% (3598/52411)
  * ruff (b302d89d) - 0% (275/269434)
  * tokio (9563707a) - 5.3% (2670/49929)
  * uv (dc5b3762) - 0% (203/132677)
  * veloren (8598d3d9) - 14.9% (46325/310550)
  * zed (83d513ae) - 1.1% (6105/560558)

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

Assignee: Роман

- отход от бескомпромиссного требования zero-cost abstractions
- перспектива существующих hardening-практик в Стандарте языка
- введение в язык профилей т.е. безопасных диалектов
- существующие инструменты миграции (`-Wunsafe-buffer-usage`)
