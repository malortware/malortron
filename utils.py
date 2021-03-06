import requests

def chunkify(text, limit):
    chunks = []
    lines = text.splitlines()
    chunk = ""
    for line in lines:
        line = f"{line}\n"
        if len(chunk + line) < limit:
            chunk += line
        else:
            chunks.append(chunk)
            chunk = line
    chunks.append(chunk)
    return chunks

NOTEBOOK_BASE_URI = "https://notes.status.im/"
def create_notebook(body=""):
    create_new_note_url = NOTEBOOK_BASE_URI + "new"
    headers = { "Content-Type": "text/markdown" }
    res = requests.post(create_new_note_url, data=body, headers=headers)
    return res.url

def get_notebook_info(notebook_url):
    res = requests.get(f"{notebook_url}/info")
    return res.json()

def get_notebook_details(notebook_url):
    res = requests.get(f"{notebook_url}/revision")
    data = res.json()
    revision = data['revision'][0]['time']
    res = requests.get(f"{notebook_url}/revision/{revision}")
    return res.json()
