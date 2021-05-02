# Počítačové komunikácie a siete - PROJEKT 2

## Variant ZETA: Sniffer paketov

**Autor:** Natália Marková <xmarko20@stud.fit.vutbr.cz>

**Jazyk:** C++

**Popis vypracovania:** <br/>
Sieťový analyzátor je implementovaný v jazyku C++. Sú v ňom využívané viaceré sieťové knižnice napr. . V mojom riešení nebol využitý filter na dané protokoly. V súbore **ipk-sniffer.cpp** sú s hlavným kódom aj s deklarácie a definície jednotlivých funkcií aj so základným popisom. \\
Súbor **Makefile** slúži sa preklad a vytvorenie binárneho súboru **ipk-sniffer**.
Program spracuváva základné argumenty špecifikované v zadaní vo funkcii **checkArgs**, kde sú pomocou *getopt* špecifikované dlhé a krátke varianty. Funkcia **sniffing**, ktorá je využívaná v hlavnom cykle pri každej iterácii. 

**Obmedzenia:** <br/>
Formát výstupu bohužiaľ nekorešponduje so zadaním, nakoľko som pre nedostatok času neimplementovala zadaný čas a veľkosť paketov.

**Rozšírenie:** <br/>
V rámci rozšírenia som implementovala funkciu **help**, ktorá po spustení programu s parametrom -h alebo dlhším --help zobrazí nápovedu k programu. Je v nej spomenuté správne spúštanie programu ako aj možnosti všetkých spustiteľných argumentov. 

**Bodové ohodnotenie:** -/20b