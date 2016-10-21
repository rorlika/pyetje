from datetime import datetime
from flask import render_template, session, redirect, url_for,flash,abort,request,current_app,make_response,jsonify
from flask.ext.login import login_required, current_user
from sqlalchemy.inspection import inspect
from flask_sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm,EditProfileAdminForm,QuestionForm,CommentForm,AnswerForm
from .. import db
from ..models import User,Permission,Question,Comment,Potoca,Category,Usertoca,Vote
from ..decorators import admin_required,permission_required

@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response

@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'

@main.route('/_add_numbers')
def add_numbers():
    a = request.args.get('catgr', 0, type=str)
    categories = Usertoca(author=current_user._get_current_object(), category_id=a)
    db.session.add(categories)
    catgr = Category.query.filter_by(id=a).first()
    return jsonify(result=catgr.name)

@main.route('/_add_vote')
def add_vote():
    result = request.args.get('result',0,type=int)
    plus_minus = request.args.get('plus_minus',0,type=int)
    question_id = request.args.get('id',0,type=int)
    query = Vote.query.filter(Vote.author_id==current_user.id , Vote.question_id==question_id).first()
    if query:
        return jsonify(message='Thanks for the feedback! Votes cast by those with less than 125 reputation are recorded, but do not change the publicly displayed post score')
    else:
        if plus_minus == 1:
            put_disabled = True
        else:
            put_disabled = False
        vote = Vote(author_id=current_user.id,question_id=question_id,disabled=put_disabled)
        db.session.add(vote)

    return jsonify(result=result + plus_minus)

@main.route('/', methods=['GET','POST'])
def index():
    form = QuestionForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        question = Question(body=form.body.data,qust=form.qust.data,
                    author=current_user._get_current_object())
        db.session.add(question)
        db.session.flush()
        s = form.categories.data
        categories = s.replace(' ','').split(',')
        for category in categories:
            cat = Category.query.filter_by(name=category).first()
            if cat is not None:
                tags = Potoca(question=question,category_id=cat.id)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    clist = []
    for x in xrange(1,13):
        cat = Category.query.filter_by(id=x).first()
        clist.append(cat.name.encode("utf-8"))
    if current_user.is_authenticated:
        categori = Category.query.join(Usertoca, Category.id == Usertoca.category_id)\
            .filter(Usertoca.author_id == current_user.id)
    else:
        categori = []
    show_followed = 0
    if current_user.is_authenticated:
       show_followed = str(request.cookies.get('show_followed', ''))
    if show_followed == '1':
       query = current_user.followed_cat
    elif show_followed == '2':
       query = current_user.followed_question
    elif show_followed == '3':
       query = Question.query.outerjoin(Comment, Question.id == Comment.question_id)\
            .filter(Comment.question_id == None)
    else:
        query = Question.query
    pagination = query.order_by(Question.timestamp.desc()).paginate(
            page,per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],error_out=False)
    questions = pagination.items
    tags = {}
    for x in questions:
        lines = Category.query.join(Potoca, Potoca.question_id == x.id)\
            .filter( Category.id == Potoca.category_id)
        ls = []
        for line in lines:
            ls.append(line.name)
        tags[x.id] = ls

    return render_template('index.html',form=form,questions=questions,\
        show_followed=show_followed,pagination=pagination,categori=categori,tags=tags,clist=clist,state=False)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp

@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

@main.route('/question_follow')
@login_required
def question_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '2', max_age=30*24*60*60)
    return resp

@main.route('/noanswers')
@login_required
def noanswers():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '3', max_age=30*24*60*60)
    return resp

@main.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    questions = user.questions.order_by(Question.timestamp.desc()).all()
    tags = {}
    for question in questions:
        lines = Category.query.join(Potoca, Potoca.question_id == question.id)\
            .filter( Category.id == Potoca.category_id)
        ls = []
        for line in lines:
            ls.append(line.name)
            tags[question.id] = ls
    return render_template('user.html',user=user,questions=questions,tags=tags)

@main.route('/edit-profile',methods=['GET','POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user',username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html',form=form)

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

@main.route('/question/<int:id>', methods=['GET', 'POST'])
def question(id):
    question = Question.query.get_or_404(id)
    checkup =  query = Vote.query.filter(Vote.author_id==current_user.id , Vote.question_id==id).first()
    minus = Vote.query.with_entities(Vote.disabled, db.func.count()).filter((Vote.disabled == 0)\
        & (Vote.question_id == id)).all()
    plus = Vote.query.with_entities(Vote.disabled, db.func.count()).filter((Vote.disabled == 1)\
        & (Vote.question_id == id)).all()
    question.votat = plus[0][1] - minus[0][1]
    db.session.add(question)
    form = CommentForm()
    if form.validate_on_submit():
        if form.submit.data:
            comment = Comment(body=form.body.data,
                              question=question,
                              author=current_user._get_current_object())
            db.session.add(comment)
            flash('Your comment has been published.')
            return redirect(url_for('.question', id=question.id, page=-1))
    question.views += 1
    db.session.add(question)
    tags = {}
    lines = Category.query.join(Potoca, Potoca.question_id == question.id)\
            .filter( Category.id == Potoca.category_id)
    ls = []
    for line in lines:
        ls.append(line.name)
    tags[question.id] = ls
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (question.comments.count() - 1) // \
            current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = question.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('question.html', questions=[question], form=form,
                           comments=comments, pagination=pagination, tags=tags,state=True,checkup=checkup)

@main.route('/category/<name>')
@login_required
def categori(name):
    categori = Category.query.filter_by(name=name).first()
    questions = categori.Question.order_by(Question.timestamp.desc()).all()
    tags = {}
    for question in questions:
        lines = Category.query.join(Potoca, Potoca.question_id == question.id)\
            .filter( Category.id == Potoca.category_id)
        ls = []
        for line in lines:
            ls.append(line.name)
            tags[question.id] = ls

    return render_template('category.html', questions=questions,tags=tags)

@main.route('/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit(id):
    question = Question.query.get_or_404(id)
    if current_user != question.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = QuestionForm()
    if form.validate_on_submit():
        question.body = form.body.data
        question.qust = form.qust.data
        db.session.add(question)
        flash('The question has been update.')
        return redirect(url_for('.question',id=question.id))
    form.body.data = question.body
    form.qust.data = question.qust
    return render_template('edit_post.html',form=form)

@main.route('/delete/<int:id>')
@login_required
def delete(id):
    question = Question.query.get_or_404(id)
    if current_user != question.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    q = Question.query.filter_by(id=id).first()
    Potoca.query.filter_by(question_id=id).delete(synchronize_session=False)
    db.session.delete(q)
    return redirect(url_for('.index'))

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))

@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))

@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page',1,type=int)
    pagination = user.followers.paginate(
        page,per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user':item.follower,'timestamp':item.timestamp}
        for item in pagination.items]
    return render_template('followers.html',user=user,title='Followers of',
        endpoint='.followers',pagination=pagination,follows=follows)

@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)

@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))
