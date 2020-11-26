# Network-Toolbox
Egyelőre a ReadMe csak magyar nyelven lesz, mivel a script teljes egészében magyarul íródott, így angol nyelvű felhasználók nem tudnának vele mit kezdeni.

## Cél
A program célja megkönnyíteni a rendszergazdák számára a hálózatra kapcsolt eszközök fizikai helyét. Mivel a legtöbb vállalati hálózat layer2-es switchekkel van kiépítve, így az alapvető traceroute parancs nem nyújt segítséget. Az általam írt script ezt a problémát igyekszik áthidalni. A script a helyi számítógép, és a lekérni kívánt eszköz MAC Addressét kigyüjtve előállítja a parancsot amely egy Cisco switchen futtatva meg tudja állapítani, hogy a távoli eszköz mely switch mely portjára csatlakozik.

## Funkciók
Az alapvető egy eszköz megtalálását elősegítő funkció mellett a program rendelkezik kibővített képességekkel, amelyek jól jöhetnek a hálózaton.

- Egy IP tartomány végigpingelése
- Egy megadott Active Directory OU-ban található gépek online állapotának lekérdezése
- Egy IP tartományba tartozó minden eszköz helyének lekérdezése
- Egy megadott Active Directory OU-ban található minden gép helyének lekérdezése A porgram az Active Directory eszközök keresésekor akár a jelen eszköztől eltérő alhálózathoz kapcsolódó eszközök megtalálására is képes. Ez a funkció egyelőre még nem működik teljesen megbízhatóan, elfogadható pontossággal csak azt képes megtalálni, hogy a hálózati eszköz melyik switchre van csatlakozva.

## Tervek
- Bugfixek (van bőven javítanivaló)
- A program képessé tétele arra, hogy a layer2-es traceroute-on kívül egyéb feladatok futtatására is képes legyen a switcheken

## Changelog
### Ver 0.7.1
- (BugFix) Switch IP cím megjelenítési hiba
- (BugFix) Eredmény kiiratási hibák javítása
- (BugFix) Hibás IP érték miatti kivételek megakadályozása
- (Fejlesztés) Layer2 Traceroute hibakezelés fejlesztése
- (Fejlesztés) CSV kimenet kezelésének bővítése
- (Fejlesztés) Debug kiiratás függvény
- (Fejlesztés) Függvények elnevezésének javítása
- (Fejlesztés) A traceroute parancshoz használt kiinduló gép pontosabb kezelése
- (Fejlesztés) Kódoptimalizáció, duplikáltan használt kódblokkok függvénybe írása
### Ver 0.7
- (BugFix) Bejelentkezett user nevének lekérésekor dobott kivétel kezelése
- (Fejlesztés) A helyi számítógéptől eltérő VLANba tartozó eszközök megtalálása (jelenleg nem stabil)
### Ver 0.6.2 (stabilnak tekinthető verzió)
- (BugFix) IP tartomány lekérésénél kimaradó IP címek hibájának javítása
- (BugFix) Beállításoktól függetlenül kimaradó logok hibájának javítása
- (Fejlesztés) Beállítási lehetőségek bővítése
### Ver 0.6.1
- (Fejlesztés) Beállítások kezelésének jelentős javítása, szétszórt, beállításokhoz kapcsolódó függvények összevonása
- (Fejlesztés) Időbélyegző hozzáadása a logokhoz
- (Fejlesztés) Fölöslegessé vált függvények törlése
### Ver 0.6
- (BugFix) Apróbb bugfixek
- (Új funkció) Active Directory OU-ban található gépek állapotának lekérdezése
- (Fejlesztés) IP címtartomány lekérdezésnél kihagyni kívánt tartomány algoritmusának javítása
### Ver 0.5.3
- (BugFix) Apróbb bugfixek
- (Fejlesztés) IP cím összehasonlító függvény hozzáadása
### Ver 0.5.2
- (Új funkció) IP cím tartományba tartozó eszközök helyének lekérdezése
- (Fejlesztés) IP címtartomány lekérdezésnél mostantól ki lehet hagyni egy szakaszt
### Ver 0.5.1
- (BugFix) Apróbb bugxfixek
### Ver 0.5 (Első stabilnak tűnő verzió)
- (Fejlesztés) Az Active Directory OU-ban található minden gép helyének megkeresése a hálózaton funkció stabillá tétele
- (BugFix) Alhálózat összevető függvény hibájának javítása
### Ver 0.4.2
- (Fejlesztés) Alhálózat összevető függvény hozzáadása
- (Fejlesztés) Kód átláthatóbbá tétele
- (BugFix) Apróbb bugfixek
### Ver 0.4.1
- (Fejlesztés) Menürendszer használatát megkönnyítő függvények hozzáadása
- (Fejlesztés) A jelenleg bejelentkezett felhasználót megállapító függvény hozzáadása
### Ver 0.4 (Első verzió ezen a néven)
- (Fork) Az Eszköz Kereső néven fejlesztett script hátrahagyása, funkcióit kibővítve új projectbe helyezése
- (Új funkció) Az Active Directory OU-ban található minden gép helyének megkeresése a hálózaton funkció stabillá tétele
