from CTF_GAME import app
from export_to_excel import export_all_to_excel

with app.app_context():
    result = export_all_to_excel()
    print(f'Export result: {result}')