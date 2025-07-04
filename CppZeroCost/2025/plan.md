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
    + libc++ checks (`_GLIBCXX_ASSERTIONS`): 3.5%
    + Asan: 4.7x

TODO:
  - в расширенном смысле харденинг - интегральная активность: правила безопасной разработки + ограничения на деплой + проверки в рантайме (в компиляторе, библиотеках, ядре ОС) + настройки ОС
    * правила безопасной разработки (и тестирования):
      + пример интегрального подхода: [Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
      + допустимые API (запрет `gets` и `rand`, предпочтение `memset_s` и т.п.)
      + static analysis (в т.ч. обязательные варнинги помимо стандартных `-Wall -Wextra -Werror`, например `-Wformat=2 -Wconversion=2`, в Visual Studio есть спец. флаг `/sdl` для таких варнингов, контракты)
      + доп. проверки (asserts, контракты и т.п.)
      + пример неудачного внедения безопасных практик: [Updated Field Experience With Annex K — Bounds Checking Interfaces](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1969.htm (2015))
    * безопасный деплой:
      + не поставлять программу с отладочной информацией (использовать separate debug info) или символьной таблицей
      + скрыть приватные символы из динамической таблицы символов
    * мы в докладе рассматриваем ТОЛЬКО рантайм-проверки в тулчейне (т.е. компиляторе и стд. библиотеках)
      + mitigation, не prevention
  - требования к харденинг: низкий оверхед + высокая точность (low false positive rate) + простота интеграции (например не ломают ABI)
  - слайд с выводами: какие флаги включить у себя в проде

# (2) Исчерпывающее перечисление: stack protector, pie, cfi, minimal ubsan, fortify, etc.

Time: 15 мин.

Assignee: Юрий

Effort: 29h

## Атаки (exploits)

Stack buffer overflow атаки (в хронологическом порядке):
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
    * испортить данные в несвязанном буфере (например указатели на функции)
    * поменять метаданные аллокатора, чтобы заставить его менять произвольные адреса
      (например поменять адрес malloc hook и вызвать его при следующем malloc,
      House of Force)
      + по этой причине malloc hooks были удалены из Glibc
  - примеры атак: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/

Распространённость buffer overflow-уязвимостей:
  - ~11% CVE и 6.5% KEV в 2024
    * 20% из них это stack overflow (самые опасные)
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
  - integer overflow:
    * ~1% CVE и 1.5% KEV в 2024
    * [Mitre CWE Top 25 2024](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html): место 23
  - неинициализированные данные

Некоторые указанные ниже методы можно детектировать в уже собранном приложении (или библиотеке)
с помощью утилиты `checksec` (но не все).

## Неисполняемый стек

- aka W^X, aka NX bit, aka Data Execution Prevention
- суть проверки:
  * отключает возможность исполнения кода в сегменте стека на уровне OS
- история:
  * одна из первых hardening защит
  * впервые появились в OpenBSD (2003) и Windows (2004)
- пример ошибки:
  * классическая атака Stack Smashing приведена [здесь](exploits/stack-smash)
  * при использовании noexecstack стабильно получаем
    ```
    Segmentation fault (core dumped)
    ```
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
  * все современные дистро стараются использовать noexecstack по умолчанию в GCC и Clang
    + на моей Debian 13 execstack включён только у программ из пакета dpkg-query
      (`/usr/bin/lksh`, etc.):
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
  * рандомизируется только базовый адрес приложения
    * хакер знает относительные смещения кода, глобальных переменных, таблиц GOT/PLT
    * если сливается адрес хотя бы одной сущности => хакер знает смещение всех остальных
    * см. про защиту GOT ниже
  * защита уязвима к info leakage
    + например [format string attach](https://en.m.wikipedia.org/wiki/Uncontrolled_format_string)
  * недостаточная рандомизация (не все биты адреса одинаково случайны, относительный порядок библиотек и программы неслучаен)
    + например в 32-битных Windows [рандомизировалось только 8 (!) битов адреса загрузки](https://cloud.google.com/blog/topics/threat-intelligence/six-facts-about-address-space-layout-randomization-on-windows/)
    + https://arxiv.org/abs/2408.15107
    + в Windows рандомизация каждого приложения делается однократно при его первой загрузке (для ускорения)
      - также одна и та же библиотека может грузиться по одному адресу в разных приложениях (для ускорения)
      - помогает только регулярный ребут сервера
    + даже в Linux рандомизация делается однократно при старте сервиса => уязвима к brute force (особенно на 32-битных платформах)
      - требуется регулярный рестарт сервисов
  * ASLR убила подход предлинковки библиотек (Prelink), использовавшийся для ускорения загрузки
- расширения:
  * некоторые коммерческие тулчейны также рандомизируют порядок функций при линковке (Safe Compiler)
  * Moving Target Defense динамически переупорядочивает сегменты в рантайме
- оверхед:
  * нет оверхеда при замерах на Clang
- сравнение с безопасными языками:
  * Rust [также собирается с `-fPIE`](https://doc.rust-lang.org/rustc/exploit-mitigations.html#position-independent-executable)
- как включить:
  * флаги `-fPIE -pie` (GCC, Clang), `/DYNAMICBASE` (Visual Studio)
  * включена по умолчанию в GCC/Clang в Ubuntu/Debian
    + можно отключить флагом `-no-pie`
  * не включена по умолчанию в компиляторах Fedora
    + можно включить флагами `-fPIE -pie`
- ссылки на статьи:
  * [проблемы ASLR в Windows](https://cloud.google.com/blog/topics/threat-intelligence/six-facts-about-address-space-layout-randomization-on-windows/)
- использование в реальных проектах
  * пакеты Fedora дефолтно собираются с `-fPIE`
    + также Ubuntu и Debian (из-за дефолтных опций компилятора)
  * много программ на Debian собраны без `-fPIE` (намного меньше на Ubuntu)
    + `for f in /usr/bin/* /usr/sbin/*; do if checksec --file=$f | grep -q 'No PIE'; then echo $f; fi; done`
    + в том числе `/usr/bin/pytho3` :(

## Stack Protector

- рядом с return address на стеке размещается специальное случайное число ("канарейка")
  * переполнение буфера это memcpy, поэтому он не может изменить RA, не изменив канарейку (а её значение неизвестно)
  * также переупорядочивает переменные: скаляры кладутся ниже по стеку чем массивы
    + чтобы при переполнении массива нельзя было модифицировать флаги и т.п.
- пример ошибки:
  * классическая атака Stack Smashing приведена [здесь](exploits/stack-smash)
  * при использовании Stack Protector стабильно получаем
    ```
    *** stack smashing detected ***: terminated
    Aborted (core dumped)
    ```
- целевые уязвимости и распространённость:
  * позволяет обнаруживать переполнение буфера перед return и соответственно ломает return-to-libc и ROP
  * см. статистику выше
- расширения:
  * аналоги канареек используются в некоторых аллокаторах для обнаружения overflow
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
- сравнение с безопасными языками
  * [Rust](https://doc.rust-lang.org/rustc/exploit-mitigations.html#stack-smashing-protection):
      + вообще коду на Rust эта опция не требуется, но она полезна в случае вызова внешних библиотек
      + есть опция для включения (`-Z stack-protector`), для обнаружения проблем с C частях программы,
        но по дефолту [отключена](https://github.com/rust-lang/compiler-team/issues/841)
- кaк включить:
  * флаг `-fstack-protector-strong` (GCC, Clang), `/GS` (Visual Studio)
  * включена по умолчанию в Ubuntu GCC и больше нигде
- ссылки на статьи:
  * https://wiki.osdev.org/Stack_Smashing_Protector
  * https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard
- использование в реальных проектах
  * пакеты в Debian и Fedora (а также Ubuntu) дефолтно собираются с `-fstack-protector-strong`

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
- целевые уязвимости и распространённость:
  * выделенной CWE для таких уязвимостей нет и непонятно как их искать
- история:
  * guard page в Linux был [внедрён в 2010](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2240)
  * [серия статей Qualys](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt) с ~10 proof of concept атаками (2017)
    + также https://www.openwall.com/lists/oss-security/2021/07/20/2
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
  * пакеты Fedora (и Ubuntu) дефолтно собираются с `-fstack-clash-protection`
  * пакеты Debian [похоже](https://github.com/jvoisin/compiler-flags-distro/issues/12) собираются пока без этого флага
  * checksec сейчас [не обнаруживает stack clash](https://github.com/slimm609/checksec/issues/300)
    + пришлось написать [свой скрипт](scripts/has_stack_clash_protection.py)
    + на Ubuntu почти все программы защищены
    + на Debian нет, даже highly-exposed программы: bash, bzip2, curl, ffmpeg, perl, python, etc.
  * Firefox [использует](https://bugzilla.mozilla.org/show_bug.cgi?id=1852202) `-fstack-clash-protection`

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
  * false negatives: неизвестны
  * в `-fsanitize=safe-stack` нет поддержки проверок в динамических библиотеках
    + их можно использовать, но они не будут использовать ShadowStack
    + возможно [поддержать их несложно](https://github.com/ossf/wg-best-practices-os-developers/issues/267#issuecomment-1835359166)
  * ShadowCallStack: только AArch64 и RISCV
- сравнение с безопасными языками
  * Rust [использует shadow stacks в найтли-сборке](https://doc.rust-lang.org/rustc/exploit-mitigations.html#stack-smashing-protection)
- как включить:
  * несколько реализаций:
    + SafeStack (`-fsanitize=safe-stack`) - [не меняет ABI](https://fuchsia.dev/fuchsia-src/concepts/kernel/safestack#interoperation_and_abi_effects)
    + Intel CET Shadow Stack (`-mshstk`) - не меняет ABI, но требует аппаратной поддержки (Intel CET)
      - TODO: как это связано с `-fcf-protection` ?
    + ShadowCallStack (`-fsanitize=shadow-call-stack` в GCC/Clang) - [не меняет ABI](https://fuchsia.dev/fuchsia-src/concepts/kernel/shadow_call_stack#interoperation_and_abi_effects)
      - AArch64-only
- ссылка на статью:
  * https://blog.includesecurity.com/2015/11/strengths-and-weaknesses-of-llvms-safestack-buffer-overflow-protection/
- использование в реальных проектах:
  * не включён по умолчанию в дистрах (даже не поддержан в текущей версии GCC в них)
  * не поддержан в checksec (можно просто искать публичный символ `__safestack_init`)

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
  * конкретный список проверяемых функций можно уточнить в реализации библиотеки
    (Glibc или Musl); как минимум:
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
- целевые уязвимости:
  * любые buffer overflow (stack, heap)
  * см. статистику выше
- история:
  * появились в Glibc 2.3.4 (2004)
  * нет аналога в Visual Studio
- возможные расширения: проверки в STL (см. ниже)
- эквивалентные отладочные проверки:
  * аналогичные проверки, но намного более эффективные и медленные, делают Asan и Valgrind
  * важно отметить что Asan [не умеет анализировать `XXX_chk`-функции](https://github.com/google/sanitizers/issues/247)
    + из-за этого использовать Asan с `_FORTIFY_SOURCE` нельзя - можно пропустить баги
    + из-за того что `_FORTIFY_SOURCE` включён по умолчанию его надо явно отключать в санитарных сборках:
      - `-U_FORTIFY_SOURCE` или `-D_FORTIFY_SOURCE=0`
    + на самом деле GCC (не Clang) вставляет доп. минимальную инструментацию в месте вызова
      для `memcpy_chk`, `memmove_chk`, `memset_chk`, но этого мало
- оверхед:
  * [`_FORTIFY_SOURCE=2` gives 3% ffmpeg overhead](https://zatoichi-engineer.github.io/2017/10/06/fortify-source.html)
  * 2% на Clang (67 сек. -> 68.5 сек. на CGBuiltin.cpp, `-D_FORTIFY_SOURCE=2`)
- проблемы:
  * false positives: неизвестны
  * false negatives
    + поддержана только в Glibc (не в musl)
    + работает только в `-O` режиме
    + компилятор далеко не всегда может вывести допустимый размер указателя из контекста
      - ограничен рамками функции
    + TODO: искать "bypassing FEATURE"
  * поддержка на разных платформах
- сравнение с безопасными языками
  * Rust включает обязательные (и неотключаемые) проверки диапазанов
- как включить:
  * для явного включения используется `-D_FORTIFY_SOURCE=2` или -`D_FORTIFY_SOURCE=3`
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
  * Debian (и Ubuntu): пакеты дефолтно собираются с `-D_FORTIFY_SOURCE=2`
  * Fedora: пакеты с 2023 дефолтно собираются с `-D_FORTIFY_SOURCE=3`

## Проверки STL

- aka "Hardened libc++"
- суть проверки:
  * зависят от компилятора и уровня проверки
  * всегда включают проверки индексов в `std::vector` и `std::string`
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
- скорее всего эти проверки станут частью Стандарта (через механизм профилей)
  * инструменты для миграции уже есть ([Safe Buffers](https://discourse.llvm.org/t/rfc-c-buffer-hardening/65734))
  * caveat: [Updated Field Experience With Annex K — Bounds Checking Interfaces](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1969.htm (2015))
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
- ссылка на хорошую статью
- использование в реальных проектах:
  * [Google: Chrome and server systems](https://security.googleblog.com/2024/11/retrofitting-spatial-safety-to-hundreds.html)
  * [Google Andromeda <1% with FDO and 2.5% without](https://bughunters.google.com/blog/6368559657254912/llvm-s-rfc-c-buffer-hardening-at-google)
  * включена для пакетов Fedora, не включена для пакетов Debian и Ubuntu

## Усиленные аллокаторы

- суть проверки:
  * дополнительные меры в динамическом аллокаторе для затруднения атак на метаданные аллокатора
- примеры реализации:
  * [Scudo](https://llvm.org/docs/ScudoHardenedAllocator.html) (дефолтный аллокатор Android)
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
  * malloc-ng (musl allocator)
    + TODO
  * Glibc
    + pointer encryption - XOR всех указателей на функции с канарейкой
    + можно вызвать в начале программы [функцию mcheck](https://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html)
      для усиленных проверок heap consistency
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
- целевые уязвимости и распространённость:
  * heap overflow, use-after-free, double free, free of invalid address
  * статистика CVE/KEV приведена выше
- TODO: история (optional)
- TODO: возможные расширения
- эквивалентные отладочные проверки: Asan, Valgrind, ElectricFence
- оверхед
  * [musl allocator 2-10x](https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance/)
    + TODO: [global lock](https://news.ycombinator.com/item?id=23081071) ?
  * hardened_malloc vs Glibc allocator: 9% на Clang (67 сек. -> 73 сек. на CGBuiltin.cpp)
- TODO: проблемы:
  * false positives и false negatives (искать "bypassing FEATURE")
  * атаки на Scudo: https://www.usenix.org/system/files/woot24-mao.pdf
  * поддержка динамических библиотек
  * поддержка на разных платформах
- сравнение с безопасными языками
  * в Rust невозможны ошибки памяти
- как включить:
  * обычно достаточно `LD_PRELOAD=path/to/new/allocator.so`
- ссылки на статьи:
  * https://www.l3harris.com/newsroom/editorial/2023/10/scudo-hardened-allocator-unofficial-internals-documentation
  * https://github.com/struct/isoalloc/blob/master/SECURITY_COMPARISON.MD
- использование в реальных проектах:
  * Android использует Scudo по дефолту
  * Chrome [использует](https://blog.chromium.org/2021/04/efficient-and-safe-allocations-everywhere.html)
    hardened-аллокатор PartitionAlloc
  * Firefox [использует](https://madaidans-insecurities.github.io/firefox-chromium.html#memory-allocator-hardening)
    не-hardened аллокатор
  * GrapheneOS использует hardned_malloc

## Защита таблиц диспетчеризации

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
- целевые уязвимости и распространённость: соответствующие CVE не найдены
  * более редкая атака чем buffer overflow, но вполне реальная:
    + смещение GOT/PLT известно
    + хакер с помощью ROP может поменять их и сделать return-to-plt
- эквивалентные отладочные проверки:
  * не существуют (ни Valgrind, ни санитары не защищают от перезаписи GOT)
- оверхед
  * замедляет только старт приложения
  * известные результаты не найдены
  * оверхед на Clang не обнаружен
- проблемы:
  * TODO: FP и FN
  * замедленное время стартапа (на разрешение символов)
  * некоторые программы могут сломаться (если в них были отсутствующие символы, которые не вызывались)
  * пользовательские таблицы функций не защищены (важно ли это ?)
- сравнение с безопасными языками
  * Rust [использует](https://doc.rust-lang.org/rustc/exploit-mitigations.html#read-only-relocations-and-immediate-binding) Full RELRO
- как включить
  * указать опции линкера: `-Wl,-z,now -Wl,-z,relro`
  * поддержка в дистрибутивах и тулчейнах:
    + Debian: не включены по умолчанию ни в GCC, ни в Clang
    + Ubuntu: включены по умолчанию в GCC, но только `-z relro` в Clang (partial RELRO)
    + Fedora: не включены по умолчанию ни в GCC, ни в Clang
- ссылка на статью:
  * https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
- использование в реальных проектах
  * Debian: пакеты дефолтно [собираются с partial RELRO](https://wiki.debian.org/HardeningWalkthrough#Selecting_security_hardening_options)
  * Fefora: пакеты дефолтно [собираются с full RELRO](https://fedoraproject.org/wiki/Security_Features_Matrix#Built_with_RELRO))
  * Ubuntu: пакеты дефолтно собираются с full RELRO

## Уменьшение зависимостей

- часто программа линкует лишние библиотеки (например из-за устаревших билдскриптов)
- от них можно избавиться без ручной модификации Makefiles с помощью флагов `-Wl,--as-needed`
  * [иногда](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html#allow-linker-to-omit-libraries-specified-on-the-command-line-to-link-against-if-they-are-not-used)
    также рекомендуют флаг `-Wl,--no-copy-dt-needed-entries`, но во-первых он не влияет на безопасность,
    а во-вторых и так включён по умолчанию в современных линкерах
- обычно эти опции используют только для ускорения стартапа, но у них есть вторичный эффект:
  * уменьшается число доступных хакеру библиотек (для поиска гаджетов)
- могут быть полезны против всех stack overflow атак, полагающихся на ROP
- TODO: целевые уязвимости и распространённость (анализ CVE):
- эквивалентные отладочные проверки: те же что у неисполняемого стека
- TODO: история
- TODO: расширения
- оверхед: отсутствует (наоборот, стартап может ускориться)
- проблемы:
  * TODO: FP и FN
  * могут сломаться некоторые программы
    + например которые использовали символы отброшенных либ с помощью `dlsym`
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
- TODO: пример ошибки
- TODO: история
- TODO: расширения
- TODO: что будет в C++26 (@Роман):
  * `[[indeterminate]]`
  * [P2795](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2795r3.html)
  * [P2723](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2723r1.html)
- эквивалентные отладочные проверки: Msan, Valgrind, [DirtyFrame](https://github.com/yugr/DirtyFrame)
- целевые уязвимости и распространённость:
  * около 50 uninitialized variable CVE в 2024 (1% от buffer overflow CVE)
  * TODO: KEV
- оверхед:
  * [1% на Firefox](https://serge-sans-paille.github.io/pythran-stories/trivial-auto-var-init-experiments.html)
  * may take over 10% on hot paths:
    + [virtio](https://patchwork-proxy.ozlabs.org/project/qemu-devel/patch/20250604191843.399309-1-stefanha@redhat.com/)
    + [Chrome](https://issues.chromium.org/issues/40633061#comment142)
  * 4.5% оверхед на Clang (67 сек. -> 70 сек. на CGBuiltin.cpp)
- проблемы
  * TODO: FP и FN
  * существенный оверхед
  * ломает обнаружение багов в Valgrind и Msan
  * инициализация нулями не всегда даёт осмысленный результат (мы скорее скрываем проблему, а не фиксим)
  * применяется только к локальным переменным (глобальные и так инициализируются, для кучи можно использовать Scudo hardened allocator)
- сравнение с безопасными языками
  * Rust заставляет программиста инициализировать переменные (или явно использовать враппер `MaybeUninit`)
  * Java заставляет программиста инициализировать локальные переменные (динамическая память гарантированно зануляется)
- как включить:
  * флаг `-ftrivial-auto-var-init=zero` (GCC, Clang), [скрытый](https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html) [флаг](https://msrc.microsoft.com/blog/2020/05/solving-uninitialized-stack-memory-on-windows/) `-initall` (Visual Studio)
- TODO: использование в реальных проектах
  * не включён по умолчанию ни в одном дистро

## Проверки целочисленного переполнения

- суть проверки:
  * существующие отладочные инструменты для проверки переполнения
    (UBsan и Isan) имеют достаточно низкий оверхед
  * их использование в проде затруднено, т.к. они используют
    большой рантайм, открывающий новые возможности для атаки
  * решение: использование "Ubsan minimal runtime"
    (немедленный аборт программы)
- TODO: пример ошибки
- TODO: целевые уязвимости и распространённость (анализ CVE/KVE):
  * CVE/KVE по integer overflow достаточно мало
  * два канонических примера: инцидент с облучателем Therac-25 и катастрофа ракеты Ariane 5
- TODO: история (optional)
- возможные расширения
  * помимо UBsan рекомендуется включать Isan (надо будет отключить инструментацию в STL RNG,
    там ест intentional unsigned overflow)
  * `-ftrapv`
- эквивалентные отладочные проверки:
  * UBsan/Isan может использоваться и как отладочный инструмент
- оверхед:
  * [до 50% на SPEC](https://arxiv.org/pdf/1711.08108)
  * 3x оверхед на Clang (69 сек. -> 204 сек. на CGBuiltin.cpp)
- проблемы
  - false positives:
    * Isan может выдавать ложные срабатывания
      (в частности нужен blacklist для кода в STL,
       полагающегося на переполнение)
  - false negatives:
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
- TODO: ссылка на хорошую статью
- использование в реальных проектах
  * не используется в дистрах
  * используется в Android media stack:
    + https://android-developers.googleblog.com/2016/05/hardening-media-stack.html
    + https://android-developers.googleblog.com/2018/06/compiler-based-security-mitigations-in.html

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
- TODO: использование в реальных проектах

## `-fhardened`

- зонтичная опция для всех hardened-оптимизаций
- включает [все опции, рекомендованные OpenSSF](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html)
- хороший дефолтный флаг, но пока реализован только в GCC
  * [Clang issue](https://github.com/llvm/llvm-project/issues/122687)
  * семантика может зависеть от версии компилятора
    + для GCC можно посмотреть функцию `print_help_hardened`, сейчас
      ```
      -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -ftrivial-auto-var-init=zero -fPIE -Wl,-z,now -Wl,-z,relro -fstack-protector-strong -fstack-clash-protection -fcf-protection=full
      ```

## TODO

Добавить инфу о проверках:
  - CFI (ARM PAC, Intel CET)
    * verify static and dynamic types match
    * also checks for dynamic types for vcalls, C++ casts, etc.
    * компиляторная инструментация
    * проблемы при немонолитное иерархии (дети в других dso), нужна спец опция и перф оверхед)
    * новые аппаратные проверки (ARM PAC, ARM BTI ~ Intel IBT (часть Intel CET))
      + включаются по `-mbranch-protection`
    * also `-fcf-protection`
    * also https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
  - Stack scrubbing (`-fstrub`)
  - `-fzero-call-used-regs` (https://www.semanticscholar.org/paper/Clean-the-Scratch-Registers%3A-A-Way-to-Mitigate-Rong-Xie/6f2ce4fd31baa0f6c02f9eb5c57b90d39fe5fa13)
  - ARM Memory Tagging Extensions

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
