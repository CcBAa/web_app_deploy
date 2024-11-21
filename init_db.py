from app import db, app

with app.app_context():
    db.create_all()
    print("資料庫已成功初始化！")
