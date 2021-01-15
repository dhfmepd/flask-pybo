import os
from datetime import datetime
from flask import current_app, Blueprint, url_for, render_template, flash, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect, secure_filename

import functools
from pybo import db
from pybo.forms import UserCreateForm, UserLoginForm, UserSettingsBaseForm, UserSettingsImageForm, UserProfileForm
from pybo.models import User

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/signup/', methods=('GET', 'POST'))
def signup():
    form = UserCreateForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            user = User(username=form.username.data,
                        password=generate_password_hash(form.password1.data),#generate_password_hash : 복호화 불가, 비교 시 암호화 후 처리.
                        email=form.email.data,
                        create_date=datetime.now())
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('main.index'))#url_for : 라우트가 설정된 함수명으로 URL을 역으로 찾아준다.
        else:
            flash('이미 존재하는 상용자입니다.')#flash : 논리오류를 발생시킨다.

    return render_template('auth/signup.html', form=form)  #render_template : 템플릿 화면을 그려준다.

@bp.route('/login/', methods=('GET', 'POST'))
def login():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        error = None
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            error = "존재하지 않는 사용자입니다."
        elif not check_password_hash(user.password, form.password.data):
            error = "비밀번호가 올바르지 않습니다."
        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('main.index'))
        flash(error)
    return render_template('auth/login.html', form=form)

@bp.route('/logout/')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

@bp.route('/settings/', methods=('GET', 'POST'))
def settings():
    ni = request.args.get('ni', type=str, default='base')
    user = User.query.get_or_404(g.user.id)

    if ni == 'base':
        if request.method == 'POST':
            form = UserSettingsBaseForm()
            if form.validate_on_submit():
                form.populate_obj(user)
                user.modify_date = datetime.now()  # 수정일시 저장
                db.session.commit()
                return redirect(url_for('main.index'))
        else:
            form = UserSettingsBaseForm(obj=user)
        return render_template('auth/settings_base.html', form=form, ni=ni)
    elif ni == 'image':
        if request.method == 'POST':
            file = request.files['profile_image']
            file_name = secure_filename(file.filename)
            file_path = os.path.join(current_app.config['UPLOAD_DIR'], file_name)
            file.save(file_path)
            return redirect(url_for('main.index'))
        return render_template('auth/settings_image.html', ni=ni)

    return render_template('auth/settings_base.html', form=form, ni=ni)

@bp.route('/profile/')
def profile():
    user = User.query.get_or_404(g.user.id)
    return render_template('auth/profile.html', user=user)

@bp.before_app_request #before_app_request : 라우트함수보타 먼저 실행
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None #g : 플라스크가 제공하는 컨텍스트 변수
    else:
        g.user = User.query.get(user_id)

#데코레이션 함수
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view