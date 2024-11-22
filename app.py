from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 使用者模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

# 任務模型
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    is_complete = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 註冊
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('註冊成功！您現在可以登入。', 'success')
        return redirect(url_for('login'))
    pass
    return render_template('register.html')

# 登入
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        # 驗證帳號和密碼
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('登入成功！', 'success')  # 儲存成功訊息
            return redirect(url_for('dashboard'))  # 重定向到使用者專區
        else:
            flash('帳號或密碼錯誤，請重新輸入。', 'danger')  # 登入失敗訊息

    return render_template('login.html')

# 忘記密碼
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # 模擬寄送驗證信
            flash(f'驗證連結已發送到您的信箱: {email}，請使用連結重設密碼。', 'success')
        else:
            flash('此 Email 未註冊，請確認後重試。', 'danger')

    return render_template('forgot_password.html')

# 使用者專區 (任務管理)
@app.route("/dashboard")
@login_required
def dashboard():
    tasks = Task.query.filter_by(owner=current_user).all()
    return render_template('dashboard.html', tasks=tasks)

# 新增任務
@app.route("/task/new", methods=['GET', 'POST'])
@login_required
def new_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date_str = request.form['due_date']
        if not title:
            flash('標題為必填項！', 'danger')
            return redirect(url_for('new_task'))

        if due_date_str:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        else:
            due_date = None

        task = Task(title=title, description=description, due_date=due_date, owner=current_user)
        db.session.add(task)
        db.session.commit()

        flash(f'任務 "{title}" 已新增！', 'success')
        return redirect(url_for('dashboard'))

    return render_template('new_task.html')

# 編輯任務
@app.route("/task/<int:task_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        abort(403)
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        due_date_str = request.form['due_date']
        task.is_complete = 'is_complete' in request.form

        if due_date_str:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        else:
            task.due_date = None

        db.session.commit()
        flash('任務已更新！', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_task.html', task=task)

# 刪除任務
@app.route("/task/<int:task_id>/delete", methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    flash('任務已刪除！', 'success')
    return redirect(url_for('dashboard'))

# 登出
@app.route("/logout")
@login_required
def logout():
    logout_user()
    pass
    return redirect(url_for('login'))
    

# 主畫面
@app.route("/") 
def home(): 
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
