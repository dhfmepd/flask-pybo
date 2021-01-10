from datetime import datetime
from sqlalchemy import func

from flask import Blueprint, render_template, request, url_for, g, flash
from werkzeug.utils import redirect

from pybo import db
from pybo.models import Question, Answer, User, Menu, question_voter
from pybo.forms import QuestionForm, AnswerForm
from pybo.views.auth_views import login_required

bp = Blueprint('question', __name__, url_prefix='/question')

@bp.route('/list/')
def _list():
    menu = request.args.get('menu', type=int, default=1)
    page = request.args.get('page', type=int, default=1)
    kw = request.args.get('kw', type=str, default='')
    so = request.args.get('so', type=str, default='recent')

    # 추천 교차 테이블 내 게시글 별 카운트 처리.
    if so == 'recommend':
        sub_query = db.session.query(question_voter.c.question_id, func.count('*').label('num_voter')) \
            .group_by(question_voter.c.question_id).subquery()
        question_list = Question.query \
            .filter_by(menu=menu) \
            .outerjoin(sub_query, Question.id == sub_query.c.question_id) \
            .order_by(sub_query.c.num_voter.desc(), Question.create_date.desc())
    elif so == 'popular':
        sub_query = db.session.query(Answer.question_id, func.count('*').label('num_answer')) \
            .group_by(Answer.question_id).subquery()
        question_list = Question.query \
            .filter_by(menu=menu) \
            .outerjoin(sub_query, Question.id == sub_query.c.question_id) \
            .order_by(sub_query.c.num_answer.desc(), Question.create_date.desc())
    else:  # recent
        question_list = Question.query \
            .filter_by(menu=menu) \
            .order_by(Question.create_date.desc())

    if kw:
        search = '%%{}%%'.format(kw)
        sub_query = db.session.query(Answer.question_id, Answer.content, User.username) \
            .join(User, Answer.user_id == User.id).subquery()

        question_list = question_list \
            .join(User) \
            .outerjoin(sub_query, sub_query.c.question_id == Question.id) \
            .filter(Question.subject.ilike(search) |  # 질문제목
                    Question.content.ilike(search) |  # 질문내용
                    User.username.ilike(search) |  # 질문작성자
                    sub_query.c.content.ilike(search) |  # 답변내용
                    sub_query.c.username.ilike(search)  # 답변작성자
                    ) \
            .distinct()
    print("QUERY[_list] :: ", question_list)
    #페이징
    question_list = question_list.paginate(page, per_page=10)
    #메뉴
    menu_list = Menu.query.order_by(Menu.sort_no.asc())

    return render_template('question/question_list.html', question_list=question_list, menu_list=menu_list,  menu=menu, page=page, kw=kw, so=so)

@bp.route('/detail/<int:question_id>/')
def detail(question_id):
    page = request.args.get('page', type=int, default=1)
    form = AnswerForm()
    
    # 질문 조회
    question = Question.query.get_or_404(question_id)

    # 조회 수 증가
    question.view_cnt = question.view_cnt + 1
    db.session.commit()
    
    # 답변 조회
    answer_list = Answer.query \
        .filter_by(question=question) \
        .order_by(Answer.create_date.desc())
    answer_list = answer_list.paginate(page, per_page=5)

    return render_template('question/question_detail.html', question=question, answer_list=answer_list, page=page, form=form)

@bp.route('/create/', methods=('GET', 'POST'))
@login_required
def create():
    menu = request.args.get('menu', type=int, default=1)
    form = QuestionForm()
    if request.method == 'POST' and form.validate_on_submit():
        question = Question(subject=form.subject.data, content=form.content.data, create_date=datetime.now(), user=g.user, menu=menu)
        db.session.add(question)
        db.session.commit()
        return redirect(url_for('main.index'))

    return render_template('question/question_form.html', form=form, menu=menu)

@bp.route('/modify/<int:question_id>', methods=('GET', 'POST'))
@login_required
def modify(question_id):
    question = Question.query.get_or_404(question_id)
    if g.user != question.user:
        flash('수정권한이 없습니다')
        return redirect(url_for('question.detail', question_id=question_id))
    if request.method == 'POST':
        form = QuestionForm()
        if form.validate_on_submit():
            form.populate_obj(question)
            question.modify_date = datetime.now()  # 수정일시 저장
            db.session.commit()
            return redirect(url_for('question.detail', question_id=question_id))
    else:
        form = QuestionForm(obj=question)
    return render_template('question/question_form.html', form=form)

@bp.route('/delete/<int:question_id>')
@login_required
def delete(question_id):
    question = Question.query.get_or_404(question_id)
    if g.user != question.user:
        flash('삭제권한이 없습니다')
        return redirect(url_for('question.detail', question_id=question_id))
    db.session.delete(question)
    db.session.commit()
    return redirect(url_for('question._list'))
