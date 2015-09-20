#!/usr/bin/python

# pywiki: a simple (private) wiki implemented in web.py
# copyright 2010 by jason pepas (jasonpepas@gmail.com)
# see https://github.com/pepaslabs/pywiki

import sys
import os
import hashlib
import fcntl
import string
import time
import cgi
import commands
import gzip
import subprocess
import binascii
import getpass
import threading
import re

import mimetypes
mimetypes.init()

import web
import creoleparser


# global utility methods


def run_or_die(command):
    """run a command, returning output.  raise an exception if it fails."""
    (status, stdio) = commands.getstatusoutput(command)
    if status != 0:
        raise Exception("command '%s' failed with exit status %d and output '%s'" % (command, status, stdio))
    return stdio

def bugout():
    session.logged_in = False
    session.kill()
    time.sleep(3)
    raise web.unauthorized()

def user_sanity_checks(i):
    MAX_USERNAME_LEN=64
    if i.user is None \
    or len(i.user) > MAX_USERNAME_LEN \
    or not i.user.isalnum() \
    or not getpass.getuser() == i.user:
        bugout()

def smscode_sanity_checks(i):
    MAX_SMSCODE_LEN = 4
    if i.smscode is None \
    or len(i.smscode) > MAX_SMSCODE_LEN \
    or not i.smscode.isalnum():
        bugout()

def grant_access():
    session.logged_in = True
    raise web.seeother('/')

def squash_unicode(text):
    # based on http://collective-docs.plone.org/troubleshooting/unicode.html
    # useful links:
    # http://en.wikipedia.org/wiki/List_of_Unicode_characters
    # http://www.utf8-chartable.de/unicode-utf8-table.pl?number=512&names=-&utf8=string-literal
    text = text.replace(u'\u00a0',' ') # non-breaking space.  this will show up as hex c2a0.
    text = text.replace(u'\u2019','\'') # right single quote.
    text = text.replace(u'\u2013','-') # "EN DASH".  just use a fucking dash already.  sheesh.
    text = text.replace(u'\u02C7','?') # caron.  this will show up as hex cb87.
    text = text.replace(u'\u00e8','e') # 'LATIN SMALL LETTER E WITH GRAVE'
    text = text.replace(u'\u00e9','e') # 'LATIN SMALL LETTER E WITH ACUTE' (U+00E9)"
    text = text.replace(u'\u00e1','a') # 'LATIN SMALL LETTER A WITH ACUTE' (U+00E1)"
    text = text.replace(u'\u00f3','o') # 'LATIN SMALL LETTER O WITH ACUTE' (U+00F3)"
    text = text.replace(u'\u201c','"') # 'LEFT DOUBLE QUOTATION MARK' (U+201C)
    text = text.replace(u'\u201d','"') # 'RIGHT DOUBLE QUOTATION MARK' (U+201D)

    return text

def list_revisions(name):
    # note: this will follow symlinks.
    archive_regex = '^%s\.(%s)\.gz$' % (name, valid_revision_regex)
    archive_pattern = re.compile(archive_regex)
    archived_page_revisions = [int(archive_pattern.match(fname).group(1)) \
                               for fname in os.listdir(archives_fpath) \
                               if archive_pattern.match(fname) \
                               and os.path.isfile(archives_fpath + fname)]
    archived_page_revisions.sort()
    return archived_page_revisions

def list_revision_mtimes(name, revisions):
    revision_times = []
    for revision in revisions:
        gzipped_fullpath = archives_fpath + '%s.%s.gz' % (name, revision)
        if os.path.isfile(gzipped_fullpath):
            revision_time = time.asctime(time.localtime(os.stat(gzipped_fullpath).st_mtime))
            revision_times.append(revision_time)
    return revision_times

def find_next_revision(name):
    revisions = list_revisions(name)
    next_revision = 0
    if len(revisions) > 0:
        next_revision = revisions[-1] + 1
    return next_revision

def uploads_fpaths():
    return [fname for fname in os.listdir(uploads_fpath) \
            if os.path.isfile(uploads_fpath + fname) and not os.path.islink(uploads_fpath + fname)]

def read_archived_page(name, revision):
    fname = '%s.%s.gz' % (name, revision)
    gzipped_fullpath = archives_fpath + fname

    contents = None
    if os.path.isfile(gzipped_fullpath):
        contents = gzip.open(gzipped_fullpath).read()
    return contents

def read_otp_passwords():
    passwds = []
    if os.path.exists(otp_fpath):
        with open(otp_fpath, 'r') as fd:
            for line in fd.readlines():
                passwds.append(line.strip())
    return passwds

def write_otp_passwords(passwords):
    if len(passwords) == 0:
        if os.path.exists(otp_fpath):
            os.unlink(otp_fpath)
    else:
        with open(otp_fpath, 'w') as fd:
            for passwd in passwords:
                fd.write('%s\n' % passwd)


class PamAuthenticator2:
    def GET(self):
        return renderer.authenticator(urlroot)

    def POST(self):
        i = web.input()
        user_sanity_checks(i)

        # I ran into a strange pam problem which seemed to be due to long-running processes.
        # breaking the pam code out into its own script as a work-around.
        # see https://twitter.com/cellularmitosis/status/641382629393043456
        cmd_fpath = '%s/pam_authenticate.py' % script_dir
        p = subprocess.Popen([cmd_fpath, i.user], stdin=subprocess.PIPE)
        p.communicate(i.passwd)
        exit_status = p.returncode

        if exit_status == 0:
            grant_access()
        else:
            bugout()


class OtpAuthenticator:
    def GET(self):
        return renderer.otpauthenticator(urlroot)

    def POST(self):
        i = web.input()
        user_sanity_checks(i)

        is_authenticated = False

        lock.acquire()
        try:
            passwds = read_otp_passwords()
            if len(passwds) > 0:
                current_passwd = passwds[0]
                if current_passwd == i.passwd:
                    is_authenticated = True
                    write_otp_passwords(passwds[1:])
        finally:
            lock.release()

        if is_authenticated == True:
            grant_access()
        else:
            bugout()


class SMSCodeRequestor:
    def generate_random_smscode(self):
        code = binascii.b2a_hex(os.urandom(2))
        return code

    def record_smscode(self, user, smscode):
        with open(ondisk_smscode_fpath, 'w') as fd:
            fd.write(smscode)
        
    def send_smscode(self, user, smscode):
        email = self.email_address_for_user(user)
        command = 'echo %s | mail -s "SMS code" %s' % (smscode, email)
        run_or_die(command)

    def email_address_for_user(self, user):
        with open(smsgateway_fpath, 'r') as fd:
            return fd.read().strip()

    def GET(self):
        return renderer.smscoderequestor(urlroot)

    def POST(self):
        lock.acquire()
        try:
            i = web.input()
            user_sanity_checks(i)
            smscode = self.generate_random_smscode()
            self.record_smscode(i.user, smscode)
            self.send_smscode(i.user, smscode)
        finally:
            time.sleep(3)
            lock.release()
        raise web.seeother('/smscodeauthenticator')


class SMSCodeAuthenticator:

    def read_ondisk_smscode(self):
        ondisk_smscode = None
        if os.path.exists(ondisk_smscode_fpath):
            with open(ondisk_smscode_fpath, 'r') as fd:
                ondisk_smscode = fd.read().strip()
        return ondisk_smscode

    def delete_ondisk_smscode(self):
        if os.path.exists(ondisk_smscode_fpath):
            os.unlink(ondisk_smscode_fpath)

    def GET(self):
        return renderer.smscodeauthenticator(urlroot)

    def POST(self):
        is_authenticated = False

        # wait for our turn, then block any other requests while we are running
        lock.acquire()
        try:
            i = web.input()
            user_sanity_checks(i)
            smscode_sanity_checks(i)

            if os.path.exists(ondisk_smscode_fpath):
                smscode_age = os.path.getmtime(ondisk_smscode_fpath)
                MAX_SMSCODE_AGE = 30
                if time.time() < (smscode_age + MAX_SMSCODE_AGE):
                    ondisk_smscode = self.read_ondisk_smscode()
                    if ondisk_smscode == i.smscode:
                        is_authenticated = True
            self.delete_ondisk_smscode()                

        finally:
            # allow other request to proceed
            lock.release()

        # forward the user in or out of the wiki
        if is_authenticated == True:
            grant_access()
        else:
            bugout()


class Deauthenticator:
    def POST(self):
        session.logged_in = False
        session.kill()
        raise web.seeother('/authenticator')


class Index:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        yyyymmdd = time.strftime('%Y%m%d')
        journal = 'Journal%s' % yyyymmdd
        return renderer.index(urlroot, journal)


class Page:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        if os.path.isfile(script_dir + '/pages/%s' % name):
            content = my_creoleparser(open(script_dir + '/pages/%s' % name).read())
            mtime = os.stat(script_dir + ('/pages/%s' % name)).st_mtime
            mtime = time.asctime(time.localtime(mtime))
            return renderer.page(urlroot, name, content, mtime)
        else:
            raise web.notfound(renderer.page404(urlroot, name))

    def POST(self,name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        page_fullpath = script_dir + ('/pages/%s' % name)

        # first, save the current version of the page as an archive
        if os.path.isfile(script_dir + ('/pages/%s' % name)):
            next_suffix = str(find_next_revision(name))
            archived_fullpath = script_dir + ('/archives/%s.%s' % (name, next_suffix))
            os.rename(page_fullpath, archived_fullpath)
            run_or_die("gzip %s" % archived_fullpath)

        # now write the new version of the page
        f = open(page_fullpath, "w")
        text = web.input(content='').content
        # squash some common unicode characters.
        text = squash_unicode(text)
        f.write(text)
        f.close()

        raise web.seeother('/page/%s' % name)


class RawPage:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        page_fpath = pages_fpath + name
        if os.path.isfile(page_fpath):
            web.header('Content-type', 'text/plain')
            return open(page_fpath).read()
        else:
            raise web.notfound()


class Editor:
    def GET(self,name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        textarea_content = ""
        page_fpath = pages_fpath + name
        if os.path.exists(page_fpath):
            # cgi.escape prevents people from putting, e.g, "</textarea>" in the edit box.
            textarea_content = cgi.escape(open(page_fpath).read())
        return renderer.editor(urlroot, name, textarea_content)


class AllPages:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        # note: this will follow symlinks.
        pages = [page for page in os.listdir(pages_fpath) if valid_pagename_pattern.match(page) and os.path.isfile(pages_fpath + page)]
        pages.sort()
        return renderer.allpages(urlroot, pages)


class RecentPages:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        # note: this will follow symlinks.
        pages = [page for page in os.listdir(pages_fpath) if valid_pagename_pattern.match(page) and os.path.isfile(pages_fpath + page)]
        revision_mtimes = [os.stat(pages_fpath + fname).st_mtime for fname in pages]
        page_tuples = sorted(zip(revision_mtimes, pages), reverse=True)
        page_tuples = [(time.asctime(time.localtime(mtime)), fname) for (mtime,fname) in page_tuples]
        return renderer.recentpages(urlroot, page_tuples)


class ArchivedPage:
    def GET(self, name, revision):
        if session.logged_in == False: raise web.seeother('/authenticator')

        contents = read_archived_page(name, revision)
        if contents is None:
            raise web.notfound()

        html = my_creoleparser(contents)
        return renderer.archive(urlroot, name, revision, html)


class RawArchivedPage:
    def GET(self, name, revision):
        if session.logged_in == False: raise web.seeother('/authenticator')

        contents = read_archived_page(name, revision)
        if contents is None:
            raise web.notfound()

        web.header('Content-type', 'text/plain')
        return contents


class ArchiveIndex:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        revisions = list_revisions(name)
        revisions.reverse()
        revision_times = list_revision_mtimes(name, revisions)

        if len(revisions) == 0:
            raise web.notfound()
        return renderer.archiveindex(urlroot, name, zip(revisions, revision_times))


class Uploader:
    def sanitize_filename(self, fname):
        # prevent any '../' tomfoolery
        fname = os.path.basename(fname)
        # only allow these characters, because we are paranoid.
        allowed_chars = string.ascii_letters + string.digits + '-_.'
        fname = ''.join([ch for ch in fname if ch in allowed_chars])
        # limit the length
        fname = fname[:256-1]
        return fname

    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        return renderer.uploader(urlroot)

    def POST(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        x = web.input(myfile={})
        filename = self.sanitize_filename(x['myfile'].filename)
        if len(filename) == 0:
            raise web.badrequest()
        open(uploads_fpath + filename, 'w').write(x['myfile'].value)
        raise web.seeother('/uploads/recent')


class Upload:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')

        if os.path.isfile(uploads_fpath + name):
            mimetype = mimetypes.guess_type(name)[0]
            web.header('Content-type', mimetype)
            data = open(uploads_fpath + name).read()
            return data
        else:
            raise web.notfound()


class AllUploads:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        uploads = sorted(uploads_fpaths())
        return renderer.alluploads(urlroot, uploads)


class RecentUploads:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')

        uploads = uploads_fpaths()
        revision_mtimes = [os.stat(uploads_fpath + fname).st_mtime for fname in uploads]
        upload_tuples = sorted(zip(revision_mtimes, uploads), reverse=True)[:50]
        upload_tuples = [(time.asctime(time.localtime(mtime)), fname) for (mtime,fname) in upload_tuples]
        return renderer.recentuploads(urlroot, upload_tuples)


# ---

(script_dir, script_file) = os.path.split(os.path.realpath(__file__))
sys.path.append(script_dir)
os.chdir(script_dir)

# base the wiki name (and urlroot) off of the script dir name.
wikiname = os.path.basename(script_dir)
urlroot = '/%s' % wikiname
web.template.Template.globals['wikititle'] = wikiname

links_baseurl = urlroot + '/page/'
my_dialect = creoleparser.dialects.creole10_base(wiki_links_base_url=(links_baseurl))
my_creoleparser = creoleparser.core.Parser(dialect=my_dialect)

lock = threading.Lock()

# regexes
valid_pagename_regex = '[a-zA-Z0-9_-]+'
valid_pagename_pattern = re.compile('^%s$' % valid_pagename_regex)
valid_revision_regex = '[0-9]+'
valid_upload_regex = '[a-zA-Z0-9_.-]+'

# routing
urls = (
    '/', 'Index',
    '/authenticator', 'PamAuthenticator2',
    '/otp', 'OtpAuthenticator',
    '/sms', 'SMSCodeRequestor',
    '/smscodeauthenticator', 'SMSCodeAuthenticator',
    '/deauthenticator', 'Deauthenticator',
    '/upload/(%s)' % valid_upload_regex, 'Upload',
    '/uploader', 'Uploader',
    '/uploads/all', 'AllUploads',
    '/uploads/recent', 'RecentUploads',
    '/pages/all', 'AllPages',
    '/pages/recent', 'RecentPages',
    '/page/(%s)' % valid_pagename_regex, 'Page',
    '/rawpage/(%s)' % valid_pagename_regex, 'RawPage',
    '/editor/(%s)' % valid_pagename_regex, 'Editor',
    '/archive/page/(%s)' % valid_pagename_regex, 'ArchiveIndex',
    '/archive/page/(%s)/(%s)' % (valid_pagename_regex, valid_revision_regex), \
        'ArchivedPage',
    '/archive/rawpage/(%s)/(%s)' % (valid_pagename_regex, valid_revision_regex), \
        'RawArchivedPage',
)

# note: sessions break when running in debug mode.
web.config.debug = False

app = web.application(urls, locals())

# compatibility with mod_wsgi
application = app.wsgifunc()

sessions_fpath = script_dir + '/sessions/'
session = web.session.Session(app, web.session.DiskStore(sessions_fpath), initializer={'logged_in': False})

templates_fpath = script_dir + '/templates/'
renderer = web.template.render(templates_fpath)

pages_fpath = script_dir + '/pages/'
archives_fpath = script_dir + '/archives/'
uploads_fpath = script_dir + '/uploads/'
smsgateway_fpath = os.environ['HOME'] + '/.smsgateway'
otp_fpath = os.environ['HOME'] + '/.otp'
ondisk_smscode_fpath = os.environ['HOME'] + '/.%s.smscode' % wikiname
ondisk_smscode_failcount_fpath = os.environ['HOME'] + '/.%s.smscode.failcount' % wikiname

