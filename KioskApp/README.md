# KioskApp: WebView2 w C# (WPF)

Przed logowaniem aplikacja pokazuje stronę na pełnym ekranie, zawsze na wierzchu.
Po zalogowaniu zmniejsza się do małego okna w prawym dolnym rogu
z nazwą użytkownika i przyciskiem „Wyloguj”. Pod spodem widać pulpit.

## Wymagania
- Windows 10/11
- .NET 8 SDK
- WebView2 Runtime (w Windows 11 jest domyślnie)

## Uruchomienie
```
dotnet run
```
Bez zmian w `appsettings.json` startuje strona demo (`wwwroot/login.html`).
Wpisz dowolną nazwę i hasło.

Publikacja do jednego folderu:
```
dotnet publish -c Release -r win-x64 --self-contained false -o publish
```

## Podłączenie własnej strony
1. W `appsettings.json` ustaw `StartUrl` (i opcjonalnie `LogoutUrl`).
2. Na stronie, po udanym logowaniu:
   ```js
   window.chrome?.webview?.postMessage({ type: 'login', user: 'Jan Kowalski' });
   ```
3. Opcjonalnie, wylogowanie ze strony:
   ```js
   window.chrome?.webview?.postMessage({ type: 'logout' });
   ```
Komunikaty są przyjmowane tylko z originu `StartUrl` (albo `TrustedOrigin`).

## Klawisze
- Alt+F4 jest zablokowane.
- **Ctrl+Alt+Shift+Q** zamyka aplikację (wyjście serwisowe).

## Autostart
Skrót do `KioskApp.exe` w `shell:startup` albo wpis w
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

## Ograniczenia
To nie jest twarda blokada. Na zwykłym koncie Windows działa Ctrl+Alt+Del,
a Win+D czy Alt+Tab mogą na chwilę pokazać pulpit (aplikacja wraca na wierzch,
gdy straci fokus). Do pełnej blokady potrzebne są zasady grupy (GPO),
np. wyłączenie Menedżera zadań i skrótów Win.
