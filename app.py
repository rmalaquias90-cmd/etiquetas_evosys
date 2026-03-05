from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from xml.etree import ElementTree as ET
from io import BytesIO
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.utils import ImageReader
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["TEMPLATES_AUTO_RELOAD"] = True
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
DB_PATH = os.path.join(app.root_path, "etiquetas.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            logo_path TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS etiquetas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            nf TEXT,
            transportadora TEXT,
            razao_social TEXT,
            endereco TEXT,
            bairro TEXT,
            cidade TEXT,
            estado TEXT,
            volumes INTEGER,
            formato TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            logo_path TEXT
        )
        """
    )
    cur.execute("INSERT OR IGNORE INTO settings(id, logo_path) VALUES (1, NULL)")
    cols = [r[1] for r in cur.execute("PRAGMA table_info(etiquetas)").fetchall()]
    if "razao_social" not in cols:
        try:
            cur.execute("ALTER TABLE etiquetas ADD COLUMN razao_social TEXT")
        except Exception:
            pass
    if "user_id" not in cols:
        try:
            cur.execute("ALTER TABLE etiquetas ADD COLUMN user_id INTEGER")
        except Exception:
            pass
    cur.execute("SELECT COUNT(1) FROM users")
    count = cur.fetchone()[0]
    if count == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin"), datetime.utcnow().isoformat()),
        )
        cur.execute("INSERT OR IGNORE INTO user_settings(user_id, logo_path) VALUES (?, NULL)", (cur.lastrowid,))
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def get_logo_path():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute("SELECT logo_path FROM user_settings WHERE user_id = ?", (uid,)).fetchone()
    conn.close()
    if not row:
        return None
    if row["logo_path"]:
        abs_path = os.path.join(app.root_path, row["logo_path"])
        if os.path.exists(abs_path):
            return abs_path
    return None

def get_logo_url():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute("SELECT logo_path FROM user_settings WHERE user_id = ?", (uid,)).fetchone()
    conn.close()
    if row and row["logo_path"]:
        return "/" + row["logo_path"].replace("\\", "/")
    return None

def is_admin():
    return session.get("username") == "admin"

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not is_admin():
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

FORMATO_OPCOES = [
    {"value": "100x50", "label": "100 x 50 mm (Padrão)", "width": 100, "height": 50},
    {"value": "100x150", "label": "100 x 150 mm", "width": 100, "height": 150},
    {"value": "80x120", "label": "80 x 120 mm", "width": 80, "height": 120},
    {"value": "60x100", "label": "60 x 100 mm", "width": 60, "height": 100},
]

FORMATO_MAP = {item["value"]: (item["width"], item["height"]) for item in FORMATO_OPCOES}


@app.route("/")
@login_required
def index():
    return render_template("form.html", formatos=FORMATO_OPCOES, logo_url=get_logo_url(), username=session.get("username"), is_admin=is_admin())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        row = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        return render_template("login.html", error="Usuário ou senha inválidos.", logo_url=get_logo_url())
    return render_template("login.html", logo_url=get_logo_url())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/importar-xml", methods=["POST"])
@login_required
def importar_xml():
    xml_file = request.files.get("xml")
    if not xml_file or xml_file.filename == "":
        return jsonify({"error": "Nenhum arquivo XML enviado."}), 400
    ok, payload_or_error = _parse_xml_file(xml_file)
    if not ok:
        return jsonify({"error": payload_or_error}), 400
    return jsonify(payload_or_error)

def _parse_xml_file(xml_file):
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError:
        return False, "XML inválido ou malformado."
    root = tree.getroot()
    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag
    def find_by_tag(name: str):
        for elem in root.iter():
            if strip_ns(elem.tag) == name:
                return elem
        return None
    def child_text(parent, name: str):
        if parent is None:
            return None
        for elem in parent.iter():
            if strip_ns(elem.tag) == name and elem.text and elem.text.strip():
                return elem.text.strip()
        return None
    def first_text(name: str):
        elem = find_by_tag(name)
        return elem.text.strip() if elem is not None and elem.text else None
    dest = find_by_tag("dest")
    transporta = find_by_tag("transporta") or find_by_tag("transportadora")
    logradouro = child_text(dest, "xLgr")
    numero = child_text(dest, "nro")
    complemento = child_text(dest, "xCpl")
    endereco = " ".join(filter(None, [logradouro, numero, complemento]))
    volumes_value = None
    for elem in root.iter():
        if strip_ns(elem.tag) != "qVol":
            continue
        text = elem.text.strip() if elem.text else ""
        if not text:
            continue
        try:
            volumes_value = max(1, int(float(text)))
            break
        except ValueError:
            continue
    payload = {
        "transportadora": child_text(transporta, "xNome") or "",
        "nf": first_text("nNF") or "",
        "razao_social": child_text(dest, "xNome") or "",
        "endereco": endereco,
        "bairro": child_text(dest, "xBairro") or "",
        "cidade": child_text(dest, "xMun") or "",
        "estado": child_text(dest, "UF") or "",
        "volumes": volumes_value or 1
    }
    return True, payload

@app.route("/importar-xmls", methods=["POST"])
@login_required
def importar_xmls():
    files = request.files.getlist("xmls")
    if not files:
        return jsonify({"error": "Nenhum arquivo XML enviado."}), 400
    items = []
    for f in files:
        if not f or not f.filename:
            continue
        ok, payload_or_error = _parse_xml_file(f)
        if ok:
            items.append(payload_or_error)
    if not items:
        return jsonify({"error": "Nenhum XML válido encontrado."}), 400
    return jsonify({"items": items})


@app.route("/gerar", methods=["POST"])
@login_required
def gerar():
    transportadora = request.form["transportadora"]
    nf = request.form["nf"]
    razao_social = request.form.get("razao_social", "")
    endereco = request.form["endereco"]
    bairro = request.form["bairro"]
    cidade = request.form["cidade"]
    estado = request.form["estado"]
    volumes = int(request.form["volumes"])
    formato = request.form.get("formato", "100x50")

    largura_mm, altura_mm = FORMATO_MAP.get(formato, FORMATO_MAP["100x150"])

    largura_pts = largura_mm * mm
    altura_pts = altura_mm * mm

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=(largura_pts, altura_pts))
    try:
        pdf.setViewerPreferences({
            "PrintScaling": "None",
            "PickTrayByPDFSize": True,
            "Duplex": "Simplex"
        })
    except Exception:
        pass

    for i in range(1, volumes + 1):
        dados = {
            "transportadora": transportadora,
            "nf": nf,
            "razao_social": razao_social,
            "endereco": endereco,
            "bairro": bairro,
            "cidade": cidade,
            "estado": estado,
            "volume_atual": i,
            "total_volumes": volumes,
            "data": datetime.now().strftime("%d/%m/%Y")
        }

        render_etiqueta(pdf, dados, largura_pts, altura_pts)

        if i < volumes:
            pdf.showPage()

    pdf.save()
    buffer.seek(0)

    conn = get_db()
    conn.execute(
        """
        INSERT INTO etiquetas (user_id, nf, transportadora, razao_social, endereco, bairro, cidade, estado, volumes, formato, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (session.get("user_id"), nf, transportadora, razao_social, endereco, bairro, cidade, estado, volumes, formato, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    nome_arquivo = f"etiqueta_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    return send_file(
        buffer,
        download_name=nome_arquivo,
        mimetype="application/pdf",
        as_attachment=True
    )

@app.route("/gerar-lote", methods=["POST"])
@login_required
def gerar_lote():
    data = request.get_json(silent=True) or {}
    items = data.get("items") or []
    formato = data.get("formato") or "100x50"
    if not items:
        return "Nenhum item recebido.", 400
    largura_mm, altura_mm = FORMATO_MAP.get(formato, FORMATO_MAP["100x50"])
    largura_pts = largura_mm * mm
    altura_pts = altura_mm * mm
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=(largura_pts, altura_pts))
    try:
        pdf.setViewerPreferences({"PrintScaling": "None", "PickTrayByPDFSize": True, "Duplex": "Simplex"})
    except Exception:
        pass
    first_page = True
    for item in items:
        transportadora = item.get("transportadora", "")
        nf = item.get("nf", "")
        razao_social = item.get("razao_social", "")
        endereco = item.get("endereco", "")
        cidade = item.get("cidade", "")
        estado = item.get("estado", "")
        volumes = int(item.get("volumes") or 1)
        for i in range(1, volumes + 1):
            dados = {
                "transportadora": transportadora,
                "nf": nf,
                "razao_social": razao_social,
                "endereco": endereco,
                "bairro": "",
                "cidade": cidade,
                "estado": estado,
                "volume_atual": i,
                "total_volumes": volumes,
                "data": datetime.now().strftime("%d/%m/%Y")
            }
            if not first_page:
                pdf.showPage()
            render_etiqueta(pdf, dados, largura_pts, altura_pts)
            first_page = False
        conn = get_db()
        conn.execute(
            """
            INSERT INTO etiquetas (user_id, nf, transportadora, razao_social, endereco, bairro, cidade, estado, volumes, formato, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session.get("user_id"), nf, transportadora, razao_social, endereco, "", cidade, estado, volumes, formato, datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
    pdf.save()
    buffer.seek(0)
    nome_arquivo = f"etiquetas_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    return send_file(buffer, download_name=nome_arquivo, mimetype="application/pdf", as_attachment=True)


def wrap_text(text: str, font_name: str, font_size: float, max_width: float):
    if not text:
        return []
    if max_width <= 0:
        return [text]

    words = text.split()
    lines = []
    current = []

    for word in words:
        candidate = " ".join(current + [word]) if current else word
        width = pdfmetrics.stringWidth(candidate, font_name, font_size)
        if width <= max_width or not current:
            current.append(word)
        else:
            lines.append(" ".join(current))
            current = [word]

    if current:
        lines.append(" ".join(current))

    return lines


def render_etiqueta(pdf_canvas: canvas.Canvas, dados: dict, largura: float, altura: float):
    min_edge = min(largura, altura)
    margem = max(4 * mm, min_edge * 0.05)
    caixa_largura = largura - margem * 2
    caixa_altura = altura - margem * 2
    header_h = max(10 * mm, min(14 * mm, altura * 0.22))
    info_x = margem + 6
    max_text_width = max(0, caixa_largura - 12)
    footer_y = margem + 16

    pdf_canvas.setStrokeColor(colors.HexColor("#1f2a37"))
    pdf_canvas.setFillColor(colors.HexColor("#ffffff"))
    pdf_canvas.setLineWidth(1.25)
    pdf_canvas.rect(margem, margem, caixa_largura, caixa_altura, stroke=1, fill=0)

    cabecalho_top = altura - margem
    logo_path = get_logo_path()
    if logo_path:
        try:
            logo_max_w = min(42 * mm, caixa_largura * 0.45)
            logo_max_h = (header_h * 0.6)
            x = info_x
            y = cabecalho_top - logo_max_h - 2
            pdf_canvas.drawImage(logo_path, x, y, width=logo_max_w, height=logo_max_h, preserveAspectRatio=False, mask='auto')
        except Exception:
            pass

    pdf_canvas.setStrokeColor(colors.HexColor("#4c6ef5"))
    pdf_canvas.setLineWidth(0.9)
    y_line = cabecalho_top - header_h + 2
    pdf_canvas.line(margem + 6, y_line, margem + caixa_largura - 6, y_line)

    scale = max(0.5, min(0.9, altura / (100 * mm)))
    current_y = cabecalho_top - int(0.55 * header_h)
    pdf_canvas.setFillColor(colors.HexColor("#1f2a37"))
    pdf_canvas.setFont("Helvetica-Bold", 12 * scale)
    pdf_canvas.drawRightString(margem + caixa_largura - 8, current_y, f"NF: {dados['nf']}")
    current_y = y_line - int(10 * scale)
    pdf_canvas.setFont("Helvetica-Bold", 10 * scale)
    pdf_canvas.drawString(info_x, current_y, "Transportadora:")
    current_y -= int(12 * scale)
    pdf_canvas.setFont("Helvetica", 10 * scale)
    for line in wrap_text(dados.get("transportadora", ""), "Helvetica", 10 * scale, max_text_width):
        pdf_canvas.drawString(info_x, current_y, line)
        current_y -= int(11 * scale)

    current_y -= int(2 * scale)
    pdf_canvas.setFont("Helvetica-Bold", 11 * scale)
    pdf_canvas.drawString(info_x, current_y, "Razão Social:")
    current_y -= int(12 * scale)
    pdf_canvas.setFont("Helvetica-Bold", 12 * scale)
    for line in wrap_text(dados.get("razao_social", ""), "Helvetica-Bold", 12 * scale, max_text_width):
        pdf_canvas.drawString(info_x, current_y, line)
        current_y -= int(12 * scale)

    current_y -= int(2 * scale)
    pdf_canvas.setFont("Helvetica-Bold", 10 * scale)
    pdf_canvas.drawString(info_x, current_y, "Endereço:")
    current_y -= int(12 * scale)
    pdf_canvas.setFont("Helvetica", 10 * scale)
    for line in wrap_text(dados.get("endereco", ""), "Helvetica", 10 * scale, max_text_width):
        pdf_canvas.drawString(info_x, current_y, line)
        current_y -= int(11 * scale)

    current_y -= int(2 * scale)
    pdf_canvas.setFont("Helvetica-Bold", 10 * scale)
    pdf_canvas.drawString(info_x, current_y, "Cidade/UF:")
    current_y -= int(12 * scale)
    pdf_canvas.setFont("Helvetica", 10 * scale)
    cidade_uf_val = (dados.get("cidade", "") or "").strip()
    uf_val = (dados.get("estado", "") or "").strip()
    if uf_val:
        cidade_uf_val = f"{cidade_uf_val}/{uf_val}" if cidade_uf_val else uf_val
    for line in wrap_text(cidade_uf_val, "Helvetica", 10 * scale, max_text_width):
        if current_y < footer_y + int(18 * scale):
            break
        pdf_canvas.drawString(info_x, current_y, line)
        current_y -= int(11 * scale)

    # (UF removido como bloco separado; já incluso em Cidade/UF)

    pdf_canvas.setLineWidth(0.5)
    pdf_canvas.setStrokeColor(colors.HexColor("#4c6ef5"))
    pdf_canvas.line(margem + 8, footer_y + 14, margem + caixa_largura - 8, footer_y + 14)

    pdf_canvas.setFont("Helvetica-Bold", 12 * scale)
    pdf_canvas.setFillColor(colors.HexColor("#1f2a37"))
    pdf_canvas.drawString(info_x, footer_y + int(4 * scale), "Volumes")
    pdf_canvas.setFont("Helvetica-Bold", 12 * scale)
    pdf_canvas.drawString(info_x, footer_y - int(6 * scale), f"{dados['volume_atual']} / {dados['total_volumes']}")

    pdf_canvas.setFont("Helvetica-Oblique", 9 * scale)
    pdf_canvas.drawRightString(margem + caixa_largura - 8, footer_y - int(8 * scale), f"Data: {dados['data']}")

@app.route("/registros")
@login_required
def registros():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, nf, transportadora, cidade, estado, volumes, formato, created_at
        FROM etiquetas
        WHERE user_id = ?
        ORDER BY datetime(created_at) DESC
        LIMIT 200
        """
    , (session.get("user_id"),)).fetchall()
    conn.close()
    return render_template("registros.html", registros=rows, logo_url=get_logo_url(), username=session.get("username"), is_admin=is_admin())

@app.route("/configuracoes", methods=["GET", "POST"])
@login_required
def configuracoes():
    message = None
    if request.method == "POST":
        file = request.files.get("logo")
        if file and file.filename:
            filename = secure_filename(file.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext not in [".png", ".jpg", ".jpeg", ".gif", ".bmp"]:
                message = "Formato de imagem inválido."
            else:
                uid = session.get("user_id")
                user_dir = os.path.join("static", "uploads", f"user_{uid}")
                abs_user_dir = os.path.join(app.root_path, user_dir)
                os.makedirs(abs_user_dir, exist_ok=True)
                save_name = f"logo{ext}"
                rel_path = os.path.join(user_dir, save_name)
                abs_path = os.path.join(app.root_path, rel_path)
                file.save(abs_path)
                conn = get_db()
                conn.execute("INSERT INTO user_settings(user_id, logo_path) VALUES(?, ?) ON CONFLICT(user_id) DO UPDATE SET logo_path=excluded.logo_path", (uid, rel_path))
                conn.commit()
                conn.close()
                message = "Logo atualizado com sucesso."
    return render_template("configuracoes.html", logo_url=get_logo_url(), message=message, username=session.get("username"), is_admin=is_admin())

@app.route("/usuarios", methods=["GET", "POST"])
@admin_required
def usuarios():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username and password:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), datetime.utcnow().isoformat()),
                )
                uid = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
                conn.execute("INSERT OR IGNORE INTO user_settings(user_id, logo_path) VALUES (?, NULL)", (uid,))
                conn.commit()
                message = "Usuário criado."
            except Exception:
                message = "Não foi possível criar o usuário."
            finally:
                conn.close()
    conn = get_db()
    users = conn.execute("SELECT id, username, created_at FROM users ORDER BY username ASC").fetchall()
    conn.close()
    return render_template("usuarios.html", users=users, message=message, logo_url=get_logo_url(), username=session.get("username"), is_admin=True)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
