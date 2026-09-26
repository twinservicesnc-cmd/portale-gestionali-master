# Portale Gestionali Master

Portale Streamlit multi-cliente per raccogliere e distribuire gestionali separati.

## Primo accesso

- Utente: `superadmin`
- Password temporanea: `CambiaSubito123!`

Cambiare la password prima della pubblicazione definitiva.

## Funzioni incluse

- catalogo dei gestionali;
- clienti separati tramite `cliente_id`;
- assegnazione di uno o più moduli a ciascun cliente;
- utenti con ruoli;
- configurazione Drive dedicata per cliente;
- registro delle attività principali;
- aggiunta di nuovi gestionali senza modificare il menu principale.

## Avvio locale

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Passi successivi

1. Collegare il database del portale a Google Drive o a un database centrale.
2. Inserire gli URL dei gestionali esistenti nel catalogo.
3. Adattare ogni gestionale per leggere `cliente_id` e la configurazione del cliente.
4. Automatizzare la creazione di cartelle Drive, credenziali e backup separati.
5. Aggiungere recupero password, 2FA e gestione licenze/scadenze.
