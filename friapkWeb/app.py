from flask import Flask, redirect, url_for, send_file, send_from_directory
from flask import render_template
from flask import request
from werkzeug.utils import secure_filename
from jinja2 import PackageLoader,Environment
from uuid import uuid4
from base.FriApk_v2 import FriApk
import os
from androguard.core.androconf import is_android
from time import strftime
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor()

app = Flask(__name__)

app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config["REPORT_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'report')

ALLOWED_EXTENSIONS = {'apk'}


@app.route('/favicon.ico')
def favicon():
    return send_file('static/android.png')


@app.route('/<name>')
def hello_world(name=None):
    return render_template("1.html".format(name))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/report/<uid>')
def report(uid=None):
    if os.path.exists(os.path.join(app.config["REPORT_DIR"], uid+'.html')):
        return send_file(f'report/{uid}.html')
    return "", 404


@app.route('/upload', methods=['GET', 'POST'])
def upload_apk():
    res = 0
    uid = ''
    if request.method == 'POST':
        # check if the post request has the file part
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename

        if file and allowed_file(file.filename):
            # filename = secure_filename(file.filename)
            uid = uuid4().hex.upper()
            apk_path = os.path.join(app.config['UP_DIR'], uid)
            file.save(apk_path)
            if is_android(apk_path) == "APK":
                executor.submit(task, apk_path=apk_path, uid=uid, upload_time=strftime("%Y-%m-%d %H:%M:%S"))
                return {'code': 1, 'msg': '', 'uuid': uid}
            else:
                return {'code': 0, 'msg': 'Invalid APK'}

        else:
            print("Upload error", file.filename)
            return {'code': 0, 'msg': '上传失败'}

    return {'code': 0, 'uuid': uid}


@app.route('/check', methods=['GET', 'POST'])
def check():
    res = {'code': 0, 'msg': "再等等嘛."}
    if request.method == "GET":
        uid = request.args.get('uuid')
        print(uid)
        if os.path.exists(os.path.join(app.config["REPORT_DIR"], uid+'.html')):
            print(uid)
            res['code'] = 1
            res['msg'] = '正在跳转...'
            return res
        return res
    else:
        return res


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def task(apk_path, uid, upload_time):
    apk = FriApk(apk_path, uid)
    res = apk.load_apk()
    create_report(res['data'], uid, upload_time)
    del res


def create_report(data, uid, upload_time):
    for k, v in data.items():
        print(k, v)
        print("-----------")
    html = render_without_request('1.html', data=data, upload_time=upload_time, uid=uid)
    with open(f'{app.config["REPORT_DIR"]}/{uid}.html', 'w', encoding='UTF-8') as f:
        f.write(html)



def render_without_request(template_name, **context):
    """
    用法同 flask.render_template:

    render_without_request('template.html', var1='foo', var2='bar')
    """
    env = Environment(
        loader=PackageLoader('friapkWeb','templates')
    )
    template = env.get_template(template_name)
    return template.render(**context)


if __name__ == '__main__':
    app.run()
