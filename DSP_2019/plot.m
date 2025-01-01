plot([10*1024, 11*1024, 13*1024], [2e6, 1.85e6, 1.8e6], '-d'); axis([9.9*1024 13.
1*1024 1.78e6 2.02e6]); xlabel 'Code size'; ylabel 'Performance'; title 'Configurati
on chart'; text(1.01 * 10*1024, 2e6, '-O4', 'fontsize', 12); text(1.01 * 11 * 1024,
1.01 * 1.85e6, '-Os', 'fontsize', 12); text(0.99 * 13*1024, 1.01 * 1.8e6, '-O2', 'fo
ntsize', 12)
