# Počítačové komunikácie a siete - PROJEKT 1

## Triviálny distribuovaný súborový systém

**Autor:** Natália Marková <xmarko20@stud.fit.vutbr.cz>

**Jazyk:** Python

**Popis vypracovania:**

Implementácia klienta pre triviálny (read-only) distribuovaný súborový systém za použitia knižnice socket. 
Využívaná UDP (klient posiela otázku na server) aj TCP (klient posiela požiadavku na server) komunikácia so serverom.<br/>
**Podporované operácie**: GET a GET ALL<br/>
**Použitie**: 
>fileget -n NAMESERVER -f SURL

Funkcia GET(), ktorá získava požadovaný súbor zo serveru a ukladá ho do zložky. Funkcia GET_ALL() získava všetky súbory zo serveru vrátane indexu (zoznam položiek serveru). V prípade chyby serveru, zlyhania komunikácie, nesprávne zadanými parametrami alebo zadaním neexistujúceho súborového serveru/požadovaného súboru sa na štandardný chybový výstup vypíše príslušné chybové hlásenie.   

**Bodové ohodnotenie:** 19b/20b
