import hashlib
import json
import os
import secrets
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken


st.set_page_config(page_title="Portale Gestionali", page_icon="🧩", layout="wide")

DATA_FILE = Path("portale_data.json")


def oggi_iso():
    return date.today().isoformat()


def data_valida(valore):
    try:
        return date.fromisoformat(str(valore))
    except (TypeError, ValueError):
        return None


def url_valido(url):
    if not url:
        return True
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def vault_key():
    """Legge la chiave di cifratura esclusivamente dai Secrets di Streamlit."""
    try:
        valore = st.secrets.get("PORTAL_VAULT_KEY", "")
    except Exception:
        valore = os.environ.get("PORTAL_VAULT_KEY", "")
    if not valore:
        return None
    try:
        return Fernet(str(valore).encode())
    except (ValueError, TypeError):
        return None


def cifra(testo):
    fernet = vault_key()
    if not fernet:
        raise ValueError("Chiave archivio credenziali non configurata")
    return fernet.encrypt(testo.encode()).decode()


def decifra(token):
    fernet = vault_key()
    if not fernet:
        raise ValueError("Chiave archivio credenziali non configurata")
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Credenziale non decifrabile con la chiave configurata") from exc


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000).hex()
    return f"{salt}:{digest}"


def password_ok(password, encoded):
    try:
        salt, expected = encoded.split(":", 1)
        actual = password_hash(password, salt).split(":", 1)[1]
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def nuovo_database():
    return {
        "versione": 1,
        "moduli": {
            "famiglia": {
                "nome": "Gestionale Famiglia", "icona": "🏠", "url": "",
                "descrizione": "Famiglia, documenti, foto, scadenze e backup.", "attivo": True,
            },
            "volley": {
                "nome": "Gestionale Volley", "icona": "🏐", "url": "",
                "descrizione": "Società, squadre, tesserati, presenze e documenti.", "attivo": True,
            },
            "ancillary": {
                "nome": "Gestionale Ancillary", "icona": "🚗", "url": "",
                "descrizione": "RA, contratti, ancillary, danni ed eventi.", "attivo": True,
            },
            "danza": {
                "nome": "Gestionale Scuola Danza", "icona": "💃", "url": "",
                "descrizione": "Iscrizioni, corsi, quote, presenze e documenti.", "attivo": True,
            },
        },
        "clienti": {},
        "utenti": {
            "superadmin": {
                "nome": "Amministratore principale",
                "password": password_hash("CambiaSubito123!"),
                "ruolo": "superadmin", "cliente_id": "", "attivo": True,
            }
        },
        "audit": [],
        "credenziali": {},
    }


def carica():
    if not DATA_FILE.exists():
        db = nuovo_database()
        salva(db)
        return db
    try:
        db = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        db = nuovo_database()
    db.setdefault("moduli", {})
    db.setdefault("clienti", {})
    db.setdefault("utenti", {})
    db.setdefault("audit", [])
    db.setdefault("credenziali", {})
    db.setdefault("versione", 1)
    # Migrazione automatica dei clienti creati dalla prima versione.
    for cliente_id, cliente in db["clienti"].items():
        cliente.setdefault("attivo", True)
        cliente.setdefault("stato_abbonamento", "attivo")
        cliente.setdefault("scadenza", "")
        if "assegnazioni" not in cliente:
            cliente["assegnazioni"] = {
                codice: {"attivo": True, "scadenza": "", "url": "", "istanza": ""}
                for codice in cliente.get("moduli", [])
            }
        for codice, assegnazione in cliente["assegnazioni"].items():
            assegnazione.setdefault("attivo", True)
            assegnazione.setdefault("scadenza", "")
            assegnazione.setdefault("url", "")
            assegnazione.setdefault("istanza", f"{codice}-{cliente_id}")
        cliente["moduli"] = list(cliente["assegnazioni"])
    db["versione"] = max(int(db.get("versione", 1)), 3)
    return db


def salva(db):
    temp = DATA_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(DATA_FILE)


def audit(db, azione):
    db["audit"].append({
        "data_ora": datetime.now().isoformat(timespec="seconds"),
        "utente": st.session_state.get("username", "sistema"),
        "azione": azione,
    })
    db["audit"] = db["audit"][-1000:]


def login(db):
    st.title("🧩 Portale Gestionali")
    st.caption("Un solo accesso per tutti i tuoi programmi.")
    with st.form("login"):
        username = st.text_input("Nome utente")
        password = st.text_input("Password", type="password")
        entra = st.form_submit_button("Accedi", type="primary", use_container_width=True)
    if entra:
        info = db["utenti"].get(username.strip())
        cliente = db["clienti"].get(info.get("cliente_id", ""), {}) if info else {}
        cliente_abilitato = (
            not info or info.get("ruolo") == "superadmin" or
            (cliente.get("attivo", True) and cliente.get("stato_abbonamento", "attivo") in {"attivo", "prova"}
             and (not data_valida(cliente.get("scadenza")) or data_valida(cliente.get("scadenza")) >= date.today()))
        )
        if (info and info.get("attivo", True) and cliente_abilitato
                and password_ok(password, info.get("password", ""))):
            st.session_state.update(
                autenticato=True, username=username.strip(), ruolo=info.get("ruolo", "utente"),
                cliente_id=info.get("cliente_id", ""),
            )
            audit(db, "Accesso riuscito")
            salva(db)
            st.rerun()
        else:
            st.error("Credenziali non valide, account disattivato oppure abbonamento scaduto.")


def moduli_disponibili(db, cliente_id, superadmin=False):
    if superadmin:
        return [(codice, modulo, {}) for codice, modulo in db["moduli"].items()
                if modulo.get("attivo", True)]
    else:
        cliente = db["clienti"].get(cliente_id, {})
        if (not cliente.get("attivo", True)
                or cliente.get("stato_abbonamento", "attivo") not in {"attivo", "prova"}):
            return []
        scadenza_cliente = data_valida(cliente.get("scadenza"))
        if scadenza_cliente and scadenza_cliente < date.today():
            return []
        autorizzati = {
            codice for codice, assegnazione in cliente.get("assegnazioni", {}).items()
            if assegnazione.get("attivo", True)
            and (not data_valida(assegnazione.get("scadenza"))
                 or data_valida(assegnazione.get("scadenza")) >= date.today())
        }
    return [(codice, modulo, cliente.get("assegnazioni", {}).get(codice, {}))
            for codice, modulo in db["moduli"].items()
            if codice in autorizzati and modulo.get("attivo", True)]


def home(db):
    superadmin = st.session_state.get("ruolo") == "superadmin"
    cliente_id = st.session_state.get("cliente_id", "")
    cliente = db["clienti"].get(cliente_id, {})
    st.title(cliente.get("nome_portale") or cliente.get("ragione_sociale") or "I tuoi gestionali")
    st.caption("Scegli il programma che vuoi utilizzare.")
    moduli = moduli_disponibili(db, cliente_id, superadmin)
    if not moduli:
        st.info("Nessun gestionale attivo è assegnato a questo account oppure l'accesso è scaduto.")
        return
    colonne = st.columns(3)
    for indice, (codice, modulo, assegnazione) in enumerate(moduli):
        with colonne[indice % 3]:
            with st.container(border=True):
                st.subheader(f"{modulo.get('icona', '🧩')} {modulo.get('nome', codice)}")
                st.write(modulo.get("descrizione", ""))
                # Per i clienti prevale sempre l'URL della loro istanza separata.
                # Il superadmin continua a poter aprire l'URL generale del catalogo.
                url = str(assegnazione.get("url") or modulo.get("url", "")).strip()
                if url:
                    st.link_button("Apri gestionale", url, use_container_width=True)
                else:
                    st.button("Indirizzo da configurare", disabled=True, key=f"no_url_{codice}", use_container_width=True)


def cambia_password(db):
    st.title("🔐 Cambia password")
    username = st.session_state.get("username", "")
    info = db["utenti"].get(username)
    if not info:
        st.error("Account non trovato.")
        return
    with st.form("cambia_password"):
        attuale = st.text_input("Password attuale", type="password")
        nuova = st.text_input("Nuova password", type="password")
        conferma = st.text_input("Conferma nuova password", type="password")
        aggiorna = st.form_submit_button("Aggiorna password", type="primary", use_container_width=True)
    if aggiorna:
        if not password_ok(attuale, info.get("password", "")):
            st.error("La password attuale non è corretta.")
        elif len(nuova) < 10:
            st.error("La nuova password deve contenere almeno 10 caratteri.")
        elif nuova != conferma:
            st.error("La conferma non corrisponde alla nuova password.")
        elif nuova == attuale:
            st.error("La nuova password deve essere diversa da quella attuale.")
        else:
            info["password"] = password_hash(nuova)
            audit(db, "Password modificata")
            salva(db)
            st.success("Password aggiornata correttamente.")


def amministrazione_clienti(db):
    st.header("🏢 Clienti")
    with st.expander("Crea nuovo cliente", expanded=not bool(db["clienti"])):
        with st.form("nuovo_cliente"):
            c1, c2 = st.columns(2)
            ragione = c1.text_input("Nome cliente / società")
            nome_portale = c2.text_input("Titolo personalizzato del portale")
            c3, c4, c5 = st.columns(3)
            colore = c3.color_picker("Colore principale", "#E63946")
            stato = c4.selectbox("Stato abbonamento", ["attivo", "sospeso", "prova"])
            scadenza = c5.date_input("Scadenza", value=date.today() + timedelta(days=365))
            moduli = st.multiselect(
                "Gestionali da assegnare", list(db["moduli"]),
                format_func=lambda x: f"{db['moduli'][x].get('icona', '')} {db['moduli'][x].get('nome', x)}",
            )
            crea = st.form_submit_button("Crea cliente", type="primary")
        if crea and ragione.strip():
            cliente_id = uuid.uuid4().hex[:12]
            db["clienti"][cliente_id] = {
                "ragione_sociale": ragione.strip(), "nome_portale": nome_portale.strip(),
                "colore": colore, "drive_folder_id": "", "moduli": moduli,
                "assegnazioni": {
                    m: {"attivo": True, "scadenza": scadenza.isoformat(), "url": "",
                        "istanza": f"{m}-{cliente_id}"} for m in moduli
                },
                "stato_abbonamento": stato, "scadenza": scadenza.isoformat(),
                "attivo": True, "creato_il": datetime.now().isoformat(timespec="seconds"),
            }
            audit(db, f"Creato cliente {ragione.strip()} ({cliente_id})")
            salva(db)
            st.success(f"Cliente creato. Codice separazione dati: {cliente_id}")
            st.rerun()

    for cliente_id, cliente in db["clienti"].items():
        with st.expander(f"{cliente.get('ragione_sociale', cliente_id)} · {cliente_id}"):
            with st.form(f"cliente_{cliente_id}"):
                c1, c2 = st.columns(2)
                nome = c1.text_input("Nome cliente", cliente.get("ragione_sociale", ""))
                titolo = c2.text_input("Titolo portale", cliente.get("nome_portale", ""))
                c3, c4, c5 = st.columns(3)
                colore = c3.color_picker("Colore", cliente.get("colore", "#E63946"))
                stato = c4.selectbox("Stato abbonamento", ["attivo", "sospeso", "prova"],
                                     index=["attivo", "sospeso", "prova"].index(cliente.get("stato_abbonamento", "attivo")))
                scadenza_attuale = data_valida(cliente.get("scadenza")) or date.today() + timedelta(days=365)
                scadenza = c5.date_input("Scadenza cliente", value=scadenza_attuale)
                moduli = st.multiselect(
                    "Gestionali autorizzati", list(db["moduli"]), default=list(cliente.get("assegnazioni", {})),
                    format_func=lambda x: db["moduli"][x].get("nome", x),
                )
                attivo = st.checkbox("Cliente attivo", cliente.get("attivo", True))
                aggiorna = st.form_submit_button("Salva cliente")
            if aggiorna:
                vecchie = cliente.get("assegnazioni", {})
                assegnazioni = {
                    m: vecchie.get(m, {"attivo": True, "scadenza": scadenza.isoformat(),
                                       "url": "", "istanza": f"{m}-{cliente_id}"})
                    for m in moduli
                }
                cliente.update(ragione_sociale=nome.strip(), nome_portale=titolo.strip(), colore=colore,
                               moduli=moduli, assegnazioni=assegnazioni, attivo=attivo,
                               stato_abbonamento=stato, scadenza=scadenza.isoformat())
                audit(db, f"Aggiornato cliente {cliente_id}")
                salva(db)
                st.success("Cliente aggiornato.")

            if cliente.get("assegnazioni"):
                st.markdown("**Stato dei gestionali assegnati**")
                for codice, assegnazione in list(cliente["assegnazioni"].items()):
                    col1, col2, col3 = st.columns([3, 2, 1])
                    nome_modulo = db["moduli"].get(codice, {}).get("nome", codice)
                    attivo_modulo = col1.checkbox(nome_modulo, assegnazione.get("attivo", True),
                                                  key=f"ass_att_{cliente_id}_{codice}")
                    scad_modulo = col2.date_input(
                        "Scadenza", value=data_valida(assegnazione.get("scadenza")) or scadenza_attuale,
                        key=f"ass_scad_{cliente_id}_{codice}", label_visibility="collapsed")
                    istanza = st.text_input(
                        "Codice istanza", assegnazione.get("istanza", f"{codice}-{cliente_id}"),
                        key=f"ass_istanza_{cliente_id}_{codice}")
                    url_istanza = st.text_input(
                        "URL specifico di questo cliente", assegnazione.get("url", ""),
                        placeholder="https://nome-app-cliente.streamlit.app",
                        key=f"ass_url_{cliente_id}_{codice}")
                    if not url_istanza:
                        st.caption("Finché l'URL specifico è vuoto viene usato quello generale del catalogo.")
                    if col3.button("Aggiorna", key=f"ass_salva_{cliente_id}_{codice}"):
                        if not url_valido(url_istanza.strip()):
                            st.error("L'URL specifico deve iniziare con http:// oppure https://.")
                            continue
                        assegnazione.update(attivo=attivo_modulo, scadenza=scad_modulo.isoformat(),
                                            url=url_istanza.strip(), istanza=istanza.strip())
                        audit(db, f"Aggiornata assegnazione {codice} per {cliente_id}")
                        salva(db)
                        st.rerun()

            utenti_cliente = [u for u, i in db["utenti"].items() if i.get("cliente_id") == cliente_id]
            st.caption(f"Utenti collegati: {len(utenti_cliente)}")
            conferma = st.checkbox("Confermo eliminazione cliente e utenti collegati", key=f"del_cliente_ok_{cliente_id}")
            if st.button("Elimina cliente", key=f"del_cliente_{cliente_id}", disabled=not conferma):
                for username in utenti_cliente:
                    db["utenti"].pop(username, None)
                db["clienti"].pop(cliente_id, None)
                db["credenziali"] = {k: v for k, v in db["credenziali"].items() if v.get("cliente_id") != cliente_id}
                audit(db, f"Eliminato cliente {cliente_id}")
                salva(db)
                st.rerun()


def amministrazione_utenti(db):
    st.header("👥 Utenti e autorizzazioni")
    clienti_attivi = {k: v for k, v in db["clienti"].items() if v.get("attivo", True)}
    with st.form("nuovo_utente"):
        c1, c2 = st.columns(2)
        username = c1.text_input("Nome utente")
        nome = c2.text_input("Nome visualizzato")
        c3, c4 = st.columns(2)
        cliente_id = c3.selectbox(
            "Cliente", [""] + list(clienti_attivi),
            format_func=lambda x: "Seleziona" if not x else clienti_attivi[x].get("ragione_sociale", x),
        )
        ruolo = c4.selectbox("Ruolo", ["amministratore cliente", "operatore", "consultazione"])
        password = st.text_input("Password iniziale", type="password")
        crea = st.form_submit_button("Crea utente", type="primary")
    if crea:
        username = username.strip()
        if not username or not password or not cliente_id:
            st.error("Compila nome utente, cliente e password.")
        elif username in db["utenti"]:
            st.error("Nome utente già esistente.")
        else:
            db["utenti"][username] = {
                "nome": nome.strip() or username, "password": password_hash(password),
                "ruolo": ruolo, "cliente_id": cliente_id, "attivo": True,
            }
            audit(db, f"Creato utente {username} per {cliente_id}")
            salva(db)
            st.success("Utente creato.")
            st.rerun()

    righe = []
    for username, info in db["utenti"].items():
        cliente = db["clienti"].get(info.get("cliente_id", ""), {})
        righe.append({"Utente": username, "Nome": info.get("nome", ""), "Ruolo": info.get("ruolo", ""),
                      "Cliente": cliente.get("ragione_sociale", "Portale Master"), "Attivo": info.get("attivo", True)})
    st.dataframe(righe, hide_index=True, use_container_width=True)

    st.markdown("#### Modifica utenti")
    for username, info in list(db["utenti"].items()):
        if username == st.session_state.get("username"):
            continue
        with st.expander(f"{info.get('nome', username)} · {username}"):
            with st.form(f"edit_user_{username}"):
                c1, c2 = st.columns(2)
                nome_edit = c1.text_input("Nome visualizzato", info.get("nome", ""))
                ruoli = ["amministratore cliente", "operatore", "consultazione"]
                ruolo_corrente = info.get("ruolo", ruoli[0])
                ruolo_edit = c2.selectbox("Ruolo", ruoli, index=ruoli.index(ruolo_corrente) if ruolo_corrente in ruoli else 0)
                attivo_edit = st.checkbox("Utente attivo", info.get("attivo", True))
                nuova_password = st.text_input("Nuova password (lascia vuoto per non cambiarla)", type="password")
                aggiorna_utente = st.form_submit_button("Salva utente")
            if aggiorna_utente:
                info.update(nome=nome_edit.strip() or username, ruolo=ruolo_edit, attivo=attivo_edit)
                if nuova_password:
                    if len(nuova_password) < 10:
                        st.error("La password deve contenere almeno 10 caratteri.")
                        continue
                    info["password"] = password_hash(nuova_password)
                audit(db, f"Aggiornato utente {username}")
                salva(db)
                st.rerun()
            conferma = st.checkbox("Confermo eliminazione utente", key=f"del_user_ok_{username}")
            if st.button("Elimina utente", key=f"del_user_{username}", disabled=not conferma):
                db["utenti"].pop(username, None)
                audit(db, f"Eliminato utente {username}")
                salva(db)
                st.rerun()


def amministrazione_moduli(db):
    st.header("🧩 Catalogo gestionali")
    st.caption("Ogni nuovo programma aggiunto qui diventa immediatamente assegnabile ai clienti.")
    with st.form("nuovo_modulo"):
        c1, c2, c3 = st.columns([1, 2, 1])
        codice = c1.text_input("Codice univoco", placeholder="es. palestra")
        nome = c2.text_input("Nome gestionale")
        icona = c3.text_input("Icona", value="🧩")
        url = st.text_input("Indirizzo dell'app")
        descrizione = st.text_input("Descrizione")
        crea = st.form_submit_button("Aggiungi al portale", type="primary")
    if crea:
        codice = "_".join(codice.strip().lower().split())
        if not codice or not nome.strip():
            st.error("Inserisci codice e nome.")
        elif codice in db["moduli"]:
            st.error("Codice già esistente.")
        elif not url_valido(url.strip()):
            st.error("L'indirizzo deve iniziare con http:// oppure https://.")
        else:
            db["moduli"][codice] = {"nome": nome.strip(), "icona": icona or "🧩", "url": url.strip(),
                                      "descrizione": descrizione.strip(), "attivo": True}
            audit(db, f"Aggiunto modulo {codice}")
            salva(db)
            st.rerun()

    for codice, modulo in db["moduli"].items():
        with st.expander(f"{modulo.get('icona', '🧩')} {modulo.get('nome', codice)}"):
            with st.form(f"modulo_{codice}"):
                c1, c2 = st.columns([3, 1])
                nome = c1.text_input("Nome", modulo.get("nome", ""), key=f"mn_{codice}")
                icona = c2.text_input("Icona", modulo.get("icona", "🧩"), key=f"mi_{codice}")
                url = st.text_input("URL", modulo.get("url", ""), key=f"mu_{codice}")
                descrizione = st.text_input("Descrizione", modulo.get("descrizione", ""), key=f"md_{codice}")
                attivo = st.checkbox("Modulo attivo", modulo.get("attivo", True), key=f"ma_{codice}")
                salva_modulo = st.form_submit_button("Salva modulo")
            if salva_modulo:
                if not nome.strip() or not url_valido(url.strip()):
                    st.error("Controlla nome e indirizzo del gestionale.")
                else:
                    modulo.update(nome=nome.strip(), icona=icona or "🧩", url=url.strip(),
                                  descrizione=descrizione.strip(), attivo=attivo)
                    audit(db, f"Aggiornato modulo {codice}")
                    salva(db)
                    st.rerun()
            assegnato = [cid for cid, c in db["clienti"].items() if codice in c.get("assegnazioni", {})]
            st.caption(f"Assegnato a {len(assegnato)} clienti")
            conferma = st.checkbox("Confermo eliminazione definitiva", key=f"del_mod_ok_{codice}")
            if st.button("Elimina gestionale", key=f"del_mod_{codice}", disabled=not conferma):
                db["moduli"].pop(codice, None)
                for cliente in db["clienti"].values():
                    cliente.get("assegnazioni", {}).pop(codice, None)
                    cliente["moduli"] = list(cliente.get("assegnazioni", {}))
                db["credenziali"] = {k: v for k, v in db["credenziali"].items() if v.get("modulo") != codice}
                audit(db, f"Eliminato modulo {codice}")
                salva(db)
                st.rerun()


def amministrazione_credenziali(db):
    st.header("🔑 Archivio credenziali")
    st.warning("Le password dei gestionali sono cifrate. Non vengono mai mostrate nelle tabelle né nel registro attività.")
    if not vault_key():
        st.error("Archivio bloccato: configura PORTAL_VAULT_KEY nei Secrets di Streamlit.")
        st.code('PORTAL_VAULT_KEY = "INCOLLA_QUI_LA_CHIAVE_GENERATA"', language="toml")
        st.caption("La chiave va conservata anche nel tuo gestore password: senza di essa le credenziali non saranno recuperabili.")
        return

    clienti = db["clienti"]
    moduli = db["moduli"]
    if not clienti or not moduli:
        st.info("Crea prima almeno un cliente e un gestionale.")
        return

    with st.form("nuova_credenziale", clear_on_submit=True):
        c1, c2 = st.columns(2)
        cliente_id = c1.selectbox("Cliente", list(clienti),
                                  format_func=lambda x: clienti[x].get("ragione_sociale", x))
        modulo = c2.selectbox("Gestionale", list(moduli),
                              format_func=lambda x: moduli[x].get("nome", x))
        c3, c4 = st.columns(2)
        username = c3.text_input("Nome utente / email")
        password = c4.text_input("Password", type="password")
        note = st.text_input("Note (senza dati sensibili)")
        crea = st.form_submit_button("Salva credenziale", type="primary")
    if crea:
        if not username.strip() or not password:
            st.error("Inserisci nome utente e password.")
        else:
            cred_id = uuid.uuid4().hex[:12]
            db["credenziali"][cred_id] = {
                "cliente_id": cliente_id, "modulo": modulo,
                "username_cifrato": cifra(username.strip()), "password_cifrata": cifra(password),
                "note": note.strip(), "aggiornata_il": datetime.now().isoformat(timespec="seconds"),
            }
            audit(db, f"Creata credenziale protetta {cred_id}")
            salva(db)
            st.success("Credenziale salvata e cifrata.")
            st.rerun()

    for cred_id, cred in list(db["credenziali"].items()):
        cliente_nome = clienti.get(cred.get("cliente_id", ""), {}).get("ragione_sociale", "Cliente rimosso")
        modulo_nome = moduli.get(cred.get("modulo", ""), {}).get("nome", "Gestionale rimosso")
        with st.expander(f"{cliente_nome} · {modulo_nome}"):
            st.write(f"Note: {cred.get('note') or '—'}")
            st.caption(f"Ultimo aggiornamento: {cred.get('aggiornata_il', '—')}")
            if st.button("Mostra per 30 secondi", key=f"show_cred_{cred_id}"):
                try:
                    st.session_state[f"cred_visible_{cred_id}"] = datetime.now().timestamp() + 30
                    st.session_state[f"cred_user_{cred_id}"] = decifra(cred["username_cifrato"])
                    st.session_state[f"cred_pass_{cred_id}"] = decifra(cred["password_cifrata"])
                    audit(db, f"Visualizzata credenziale protetta {cred_id}")
                    salva(db)
                except ValueError as exc:
                    st.error(str(exc))
            scade = st.session_state.get(f"cred_visible_{cred_id}", 0)
            if scade > datetime.now().timestamp():
                st.text_input("Nome utente", st.session_state.get(f"cred_user_{cred_id}", ""),
                              disabled=True, key=f"shown_user_{cred_id}")
                st.text_input("Password", st.session_state.get(f"cred_pass_{cred_id}", ""),
                              disabled=True, key=f"shown_pass_{cred_id}")
                st.caption("I dati saranno nascosti automaticamente al prossimo aggiornamento dopo 30 secondi.")
            with st.form(f"update_cred_{cred_id}"):
                nuovo_username = st.text_input("Nuovo nome utente (facoltativo)")
                nuova_password = st.text_input("Nuova password (facoltativa)", type="password")
                nuove_note = st.text_input("Note", cred.get("note", ""))
                aggiorna = st.form_submit_button("Aggiorna credenziale")
            if aggiorna:
                if nuovo_username.strip():
                    cred["username_cifrato"] = cifra(nuovo_username.strip())
                if nuova_password:
                    cred["password_cifrata"] = cifra(nuova_password)
                cred.update(note=nuove_note.strip(), aggiornata_il=datetime.now().isoformat(timespec="seconds"))
                audit(db, f"Aggiornata credenziale protetta {cred_id}")
                salva(db)
                st.rerun()
            conferma = st.checkbox("Confermo eliminazione credenziale", key=f"del_cred_ok_{cred_id}")
            if st.button("Elimina credenziale", key=f"del_cred_{cred_id}", disabled=not conferma):
                db["credenziali"].pop(cred_id, None)
                audit(db, f"Eliminata credenziale protetta {cred_id}")
                salva(db)
                st.rerun()


def amministrazione_riepilogo(db):
    st.header("📊 Riepilogo")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Clienti", len(db["clienti"]))
    c2.metric("Utenti", len(db["utenti"]))
    c3.metric("Gestionali", len(db["moduli"]))
    c4.metric("Credenziali protette", len(db["credenziali"]))
    righe = []
    for cliente_id, cliente in db["clienti"].items():
        scadenza = data_valida(cliente.get("scadenza"))
        giorni = (scadenza - date.today()).days if scadenza else None
        stato = cliente.get("stato_abbonamento", "attivo")
        if scadenza and giorni < 0:
            stato = "scaduto"
        righe.append({
            "Cliente": cliente.get("ragione_sociale", cliente_id),
            "Codice": cliente_id,
            "Stato": stato,
            "Scadenza": cliente.get("scadenza", ""),
            "Giorni residui": giorni,
            "Gestionali assegnati": len(cliente.get("assegnazioni", {})),
            "Utenti": sum(1 for u in db["utenti"].values() if u.get("cliente_id") == cliente_id),
        })
    if righe:
        st.dataframe(righe, hide_index=True, use_container_width=True)
    else:
        st.info("Nessun cliente inserito.")


def amministrazione(db):
    st.title("⚙️ Amministrazione Portale Master")
    tab0, tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Riepilogo", "Clienti", "Utenti", "Gestionali", "Credenziali", "Registro attività"]
    )
    with tab0:
        amministrazione_riepilogo(db)
    with tab1:
        amministrazione_clienti(db)
    with tab2:
        amministrazione_utenti(db)
    with tab3:
        amministrazione_moduli(db)
    with tab4:
        amministrazione_credenziali(db)
    with tab5:
        st.dataframe(list(reversed(db["audit"])), hide_index=True, use_container_width=True)


db = carica()
if not st.session_state.get("autenticato"):
    login(db)
    st.stop()

with st.sidebar:
    st.title("🧩 Portale")
    info_utente = db["utenti"].get(st.session_state.get("username", ""), {})
    st.write(f"👤 {info_utente.get('nome', st.session_state.get('username', ''))}")
    voci = ["🏠 I miei gestionali", "🔐 Cambia password"]
    if st.session_state.get("ruolo") == "superadmin":
        voci.append("⚙️ Amministrazione")
    pagina = st.radio("Menu", voci)
    if st.button("Esci", use_container_width=True):
        for chiave in ["autenticato", "username", "ruolo", "cliente_id"]:
            st.session_state.pop(chiave, None)
        st.rerun()

if pagina == "⚙️ Amministrazione":
    amministrazione(db)
elif pagina == "🔐 Cambia password":
    cambia_password(db)
else:
    home(db)
