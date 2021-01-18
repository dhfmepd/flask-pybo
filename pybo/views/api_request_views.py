from datetime import datetime
from sqlalchemy import func

from urllib.request import urlopen
from urllib.parse import quote

from bs4 import BeautifulSoup

from flask import Blueprint, render_template, request, url_for, g, flash
from werkzeug.utils import redirect

from pybo import db
from pybo.models import Apireq, Apires, User
from pybo.forms import ApireqForm
from pybo.views.auth_views import login_required

bp = Blueprint('api_request', __name__, url_prefix='/api/request')

@bp.route('/list/')
def _list():
    page = request.args.get('page', type=int, default=1)
    kw = request.args.get('kw', type=str, default='')
    so = request.args.get('so', type=str, default='recent')

    # 추천 교차 테이블 내 게시글 별 카운트 처리.
    if so == 'popular':
        sub_query = db.session.query(Apires.apireq_id, func.count('*').label('num_apires')) \
            .group_by(Apires.apireq_id).subquery()
        apireq_list = Apireq.query \
            .outerjoin(sub_query, Apireq.id == sub_query.c.apireq_id) \
            .order_by(sub_query.c.num_apires.desc(), Apireq.create_date.desc())
    else:  # recent
        apireq_list = Apireq.query \
            .order_by(Apireq.create_date.desc())

    if kw:
        search = '%%{}%%'.format(kw)
        apireq_list = apireq_list \
            .join(User) \
            .filter(Apireq.subject.ilike(search) |  # 질문제목
                    User.username.ilike(search)   # 질문작성자
                    ) \
            .distinct()
    print("QUERY[_list] :: ", apireq_list)
    #페이징
    apireq_list = apireq_list.paginate(page, per_page=10)

    return render_template('api/request/list.html', apireq_list=apireq_list, page=page, kw=kw, so=so)

@bp.route('/create/', methods=('GET', 'POST'))
def create():
    form = ApireqForm()
    if request.method == 'POST' and form.validate_on_submit():
        apireq = Apireq(subject=form.subject.data,
                  service_key=form.service_key.data,
                  target_url=form.target_url.data,
                  parameter=form.parameter.data,
                  data_type='XML',
                  create_date=datetime.now(),
                  user=g.user)
        db.session.add(apireq)
        db.session.commit()
        return redirect(url_for('api_request._list'))

    return render_template('api/request/form.html', form=form)


@bp.route('/detail/<int:apireq_id>/')
def detail(apireq_id):
    page = request.args.get('page', type=int, default=1)

    # 조회
    apireq = Apireq.query.get_or_404(apireq_id)

    # 결과 조회
    apires_list = Apires.query \
        .filter_by(apireq=apireq) \
        .order_by(Apires.create_date.desc())

    apires_list = apires_list.paginate(page, per_page=5)

    return render_template('api/request/detail.html', apireq=apireq, apires_list=apires_list, page=page)

@bp.route('/modify/<int:apireq_id>', methods=('GET', 'POST'))
@login_required
def modify(apireq_id):
    apireq = Apireq.query.get_or_404(apireq_id)
    if g.user != apireq.user:
        flash('수정권한이 없습니다')
        return redirect(url_for('api_request.detail', apireq_id=apireq_id))
    if request.method == 'POST':
        form = ApireqForm()
        if form.validate_on_submit():
            form.populate_obj(apireq)
            apireq.modify_date = datetime.now()  # 수정일시 저장
            db.session.commit()
            return redirect(url_for('api_request.detail', apireq_id=apireq_id))
    else:
        form = ApireqForm(obj=apireq)

    return render_template('api/request/form.html', form=form)

@bp.route('/delete/<int:apireq_id>')
@login_required
def delete(apireq_id):
    apireq = Apireq.query.get_or_404(apireq_id)
    if g.user != apireq.user:
        flash('삭제권한이 없습니다')
        return redirect(url_for('api_request.detail', apireq_id=apireq_id))
    db.session.delete(apireq)
    db.session.commit()
    return redirect(url_for('api_request._list'))

@bp.route('/call/<int:apireq_id>')
def call(apireq_id):
    # 조회
    apireq = Apireq.query.get_or_404(apireq_id)

    #Loop 처리로 변경 필요.
    parameter = '?ServiceKey=' + apireq.service_key + "&numOfRows=10&pageNo=1&sidoName=" + quote("서울") + "&searchCondition=HOUR"
    print("Target URL ===== ", apireq.target_url)
    print("Parameter ===== ", parameter)
    response_body = urlopen(apireq.target_url + parameter).read().decode("utf-8")
    print('Response ===== ', response_body)
    soup = BeautifulSoup(response_body, 'html.parser')
    items = soup.findAll('item')

    for item in items:
        print("CTIY NAME == ", item.find('cityname').string)
        print("PM10 == ", item.find('pm10value').string)

    apires = Apires(parameter=apireq.parameter,
                    data_type=apireq.data_type,
                    result_data=response_body,
                    create_date=datetime.now(),
                    user=g.user)
    apireq.apires_set.append(apires)
    db.session.commit()

    return redirect(url_for('api_request.detail', apireq_id=apireq_id))