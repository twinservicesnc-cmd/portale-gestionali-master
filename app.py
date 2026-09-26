import hashlib
import json
import secrets
import uuid
from datetime import datetime
from pathlib import Path

import streamlit as st


st.set_page_config(page_title="Portale Gestionali", page_icon="🧩", layout="wide")

DATA_FILE = Path("portale_data.json")


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
        if info and info.get("attivo", True) and password_ok(password, info.get("password", "")):
            st.session_state.update(
                autenticato=True, username=username.strip(), ruolo=info.get("ruolo", "utente"),
                cliente_id=info.get("cliente_id", ""),
            )
            audit(db, "Accesso riuscito")
            salva(db)
            st.rerun()
        else:
            st.error("Credenziali non valide o account disattivato.")


def moduli_disponibili(db, cliente_id, superadmin=False):
    if superadmin:
        autorizzati = set(db["moduli"])
    else:
        autorizzati = set(db["clienti"].get(cliente_id, {}).get("moduli", []))
    return [(codice, modulo) for codice, modulo in db["moduli"].items()
            if codice in autorizzati and modulo.get("attivo", True)]


def home(db):
    superadmin = st.session_state.get("ruolo") == "superadmin"
    cliente_id = st.session_state.get("cliente_id", "")
    cliente = db["clienti"].get(cliente_id, {})
    st.title(cliente.get("nome_portale") or cliente.get("ragione_sociale") or "I tuoi gestionali")
    st.caption("Scegli il programma che vuoi utilizzare.")
    moduli = moduli_disponibili(db, cliente_id, superadmin)
    if not moduli:
        st.info("Nessun gestionale è stato ancora assegnato a questo account.")
        return
    colonne = st.columns(3)
    for indice, (codice, modulo) in enumerate(moduli):
        with colonne[indice % 3]:
            with st.container(border=True):
                st.subheader(f"{modulo.get('icona', '🧩')} {modulo.get('nome', codice)}")
                st.write(modulo.get("descrizione", ""))
                url = str(modulo.get("url", "")).strip()
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
            c3, c4 = st.columns(2)
            colore = c3.color_picker("Colore principale", "#E63946")
            cartella_drive = c4.text_input("ID cartella Google Drive dedicata")
            moduli = st.multiselect(
                "Gestionali da assegnare", list(db["moduli"]),
                format_func=lambda x: f"{db['moduli'][x].get('icona', '')} {db['moduli'][x].get('nome', x)}",
            )
            crea = st.form_submit_button("Crea cliente", type="primary")
        if crea and ragione.strip():
            cliente_id = uuid.uuid4().hex[:12]
            db["clienti"][cliente_id] = {
                "ragione_sociale": ragione.strip(), "nome_portale": nome_portale.strip(),
                "colore": colore, "drive_folder_id": cartella_drive.strip(),
                "moduli": moduli, "attivo": True, "creato_il": datetime.now().isoformat(timespec="seconds"),
            }
            audit(db, f"Creato cliente {ragione.strip()} ({cliente_id})")
            salva(db)
            st.success(f"Cliente creato. Codice separazione dati: {cliente_id}")
            st.rerun()

    for cliente_id, cliente in db["clienti"].items():
        with st.expander(f"{cliente.get('ragione_sociale', cliente_id)} · {cliente_id}"):
            with st.form(f"cliente_{cliente_id}"):
                nome = st.text_input("Nome cliente", cliente.get("ragione_sociale", ""))
                titolo = st.text_input("Titolo portale", cliente.get("nome_portale", ""))
                colore = st.color_picker("Colore", cliente.get("colore", "#E63946"))
                drive = st.text_input("ID cartella Drive", cliente.get("drive_folder_id", ""))
                moduli = st.multiselect(
                    "Moduli autorizzati", list(db["moduli"]), default=cliente.get("moduli", []),
                    format_func=lambda x: db["moduli"][x].get("nome", x),
                )
                attivo = st.checkbox("Cliente attivo", cliente.get("attivo", True))
                aggiorna = st.form_submit_button("Salva cliente")
            if aggiorna:
                cliente.update(ragione_sociale=nome.strip(), nome_portale=titolo.strip(), colore=colore,
                               drive_folder_id=drive.strip(), moduli=moduli, attivo=attivo)
                audit(db, f"Aggiornato cliente {cliente_id}")
                salva(db)
                st.success("Cliente aggiornato.")


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
        else:
            db["moduli"][codice] = {"nome": nome.strip(), "icona": icona or "🧩", "url": url.strip(),
                                      "descrizione": descrizione.strip(), "attivo": True}
            audit(db, f"Aggiunto modulo {codice}")
            salva(db)
            st.rerun()

    for codice, modulo in db["moduli"].items():
        with st.expander(f"{modulo.get('icona', '🧩')} {modulo.get('nome', codice)}"):
            with st.form(f"modulo_{codice}"):
                nome = st.text_input("Nome", modulo.get("nome", ""), key=f"mn_{codice}")
                url = st.text_input("URL", modulo.get("url", ""), key=f"mu_{codice}")
                descrizione = st.text_input("Descrizione", modulo.get("descrizione", ""), key=f"md_{codice}")
                attivo = st.checkbox("Modulo attivo", modulo.get("attivo", True), key=f"ma_{codice}")
                salva_modulo = st.form_submit_button("Salva modulo")
            if salva_modulo:
                modulo.update(nome=nome.strip(), url=url.strip(), descrizione=descrizione.strip(), attivo=attivo)
                audit(db, f"Aggiornato modulo {codice}")
                salva(db)
                st.success("Modulo aggiornato.")


def amministrazione(db):
    st.title("⚙️ Amministrazione Portale Master")
    tab1, tab2, tab3, tab4 = st.tabs(["Clienti", "Utenti", "Gestionali", "Registro attività"])
    with tab1:
        amministrazione_clienti(db)
    with tab2:
        amministrazione_utenti(db)
    with tab3:
        amministrazione_moduli(db)
    with tab4:
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
