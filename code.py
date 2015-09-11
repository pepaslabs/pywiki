#!/usr/bin/python

# pywiki: a simple (private) wiki implemented in web.py
# copyright 2010 by jason pepas (jasonpepas@gmail.com)
# see https://github.com/pepaslabs/pywiki

import web
import sys
import hashlib
import os
import os.path
import fcntl
import string
import time
import cgi
import re
import mimetypes
mimetypes.init()
import commands
import gzip
import subprocess


(script_dir, script_file) = os.path.split(os.path.realpath(__file__))
sys.path.append(script_dir)
os.chdir(script_dir)

# base the wiki name (and urlroot) off of the script dir name.
wikiname = os.path.basename(script_dir)
urlroot = '/%s' % wikiname
web.template.Template.globals['wikititle'] = wikiname

valid_upload_regex = '[a-zA-Z0-9_.-]+'
valid_pagename_regex = '[a-zA-Z0-9_-]+'
valid_revision_regex = '[0-9]+'

valid_pagename_pattern = re.compile('^%s$' % valid_pagename_regex)

urls = (
    '/', 'Index',
    '/authenticator', 'PamAuthenticator2',
    '/otpauthenticator', 'OtpAuthenticator',
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

app = web.application(urls, locals())
# this is for compatibility with mod_wsgi
application = app.wsgifunc()
# sessions break when running in debug mode.
web.config.debug = False
session = web.session.Session(app, web.session.DiskStore(script_dir + '/sessions/'), \
                              initializer={'logged_in': False})
renderer = web.template.render(script_dir + '/templates/')


def run_or_die(command):
    """run a command, returning output.  raise an exception if it fails."""
    (status, stdio) = commands.getstatusoutput(command)
    if status != 0:
        raise Exception("command '%s' failed with exit status %d and output '%s'" % (command, status, stdio))
    return stdio


MAX_USERNAME_LEN=64

def _bugout():
    session.logged_in = False
    session.kill()
    raise web.unauthorized()

def _input_sanity_checks(i):
    if len(i.user) > MAX_USERNAME_LEN \
    or not i.user.isalnum():
        _bugout()

def _grant_access():
    session.logged_in = True
    raise web.seeother('/')


class PamAuthenticator2:
    def GET(self):
        return renderer.authenticator(urlroot)

    def POST(self):
        i = web.input()
        _input_sanity_checks(i)

        # I ran into a strange pam problem which seemed to be due to long-running processes.
        # breaking the pam code out into its own script as a work-around.
        # see https://twitter.com/cellularmitosis/status/641382629393043456
        p = subprocess.Popen(['%s/pam_authenticate.py' % script_dir, i.user], stdin=subprocess.PIPE)
        p.communicate(i.passwd)
        exit_status = p.returncode

        if exit_status == 0:
            _grant_access()
        else:
            _bugout()



class OtpAuthenticator:
    def GET(self):
        return renderer.otpauthenticator(urlroot)

    def POST(self):
        i = web.input()
        _input_sanity_checks(i)
        fd = open(os.environ['HOME'] + '/.otp','r+')
        fcntl.flock(fd,fcntl.LOCK_EX)
        passwds = []
        for line in fd.readlines():
            passwds.append(line.strip())
        current_passwd = passwds[0]
        try:
            print "->%s<- == ->%s<-" % (current_passwd, i.passwd)
            assert current_passwd == i.passwd
        except:
            fcntl.flock(fd,fcntl.LOCK_UN)
            fd.close()
            webauth._bugout()
        else:
            fd.seek(0)
            fd.truncate()
            for passwd in passwds[1:]:
                fd.write('%s\n' % passwd)
            fcntl.flock(fd,fcntl.LOCK_UN)
            fd.close()
            _grant_access()


class Deauthenticator:
    def POST(self):
        session.logged_in = False
        session.kill()
        raise web.seeother('/authenticator')


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



import creoleparser
my_dialect = creoleparser.dialects.creole10_base(wiki_links_base_url=(urlroot + '/page/'))
my_creoleparser = creoleparser.core.Parser(dialect=my_dialect)


class Index:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        yyyymmdd = time.strftime('%Y%m%d')
        journal = 'Journal%s' % yyyymmdd
        return renderer.index(urlroot, journal)


def list_revisions(name):
    archive_pattern = re.compile('^%s\.(%s)(\.gz)?$' % (name, valid_revision_regex))
    # note: this will follow symlinks.
    archived_page_revisions = [int(archive_pattern.match(fname).group(1)) \
                               for fname in os.listdir(script_dir + '/archives/') \
                               if archive_pattern.match(fname) \
                               and os.path.isfile(script_dir + '/archives/%s' % fname)]
    archived_page_revisions.sort()
    return archived_page_revisions


def find_next_revision(name):
    revisions = list_revisions(name)
    next_revision = 0
    if len(revisions) > 0:
        next_revision = revisions[-1] + 1
    return next_revision


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
        if os.path.isfile(script_dir + ('/pages/%s' % name)):
            web.header('Content-type', 'text/plain')
            return open(script_dir + ('/pages/%s' % name)).read()
        else:
            raise web.notfound()


class Editor:
    def GET(self,name):
        if session.logged_in == False: raise web.seeother('/authenticator')
        textarea_content = ""
        if os.path.exists(script_dir + ('/pages/%s' % name)):
            # cgi.escape prevents people from putting, e.g, "</textarea>" in
            # the edit box.
            textarea_content = cgi.escape(open(script_dir + ('/pages/%s' % name)).read())
        return renderer.editor(urlroot, name, textarea_content)


class AllPages:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        # note: this will follow symlinks.
        pages = [page for page in os.listdir(script_dir + '/pages/') \
                 if valid_pagename_pattern.match(page) \
                 and os.path.isfile(script_dir + ('/pages/%s' % page))]
        pages.sort()
        return renderer.allpages(urlroot, pages)


class RecentPages:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        # note: this will follow symlinks.
        pages = [fname for fname in os.listdir(script_dir + '/pages/') \
                 if os.path.isfile(script_dir + ('/pages/%s' % fname))]
        revision_mtimes = [os.stat(script_dir + ('/pages/%s' % fname)).st_mtime \
                           for fname in pages]
        page_tuples = sorted(zip(revision_mtimes, pages), reverse=True)
        page_tuples = [(time.asctime(time.localtime(mtime)), fname) \
                       for (mtime,fname) in page_tuples]
        return renderer.recentpages(urlroot, page_tuples)


class ArchivedPage:
    def GET(self, name, revision):
        if session.logged_in == False: raise web.seeother('/authenticator')
        archived_fullpath = script_dir + ('/archives/%s.%s' % (name, revision))
        gzipped_fullpath = archived_fullpath + '.gz'

        contents = None
        if (os.path.isfile(archived_fullpath)):
            contents = open(archived_fullpath).read()
        elif (os.path.isfile(gzipped_fullpath)):
            contents = gzip.open(gzipped_fullpath).read()
        else:
            raise web.notfound()

        html = my_creoleparser(contents)
        return renderer.archive(urlroot, name, revision, html)


class RawArchivedPage:
    def GET(self, name, revision):
        if session.logged_in == False: raise web.seeother('/authenticator')
        archived_fullpath = script_dir + ('/archives/%s.%s' % (name, revision))
        gzipped_fullpath = archived_fullpath + '.gz'

        contents = None
        if (os.path.isfile(archived_fullpath)):
            contents = open(archived_fullpath).read()
        elif (os.path.isfile(gzipped_fullpath)):
            contents = gzip.open(gzipped_fullpath).read()
        else:
            raise web.notfound()

        web.header('Content-type', 'text/plain')
        return contents


class ArchiveIndex:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')
        revisions = list_revisions(name)
        revisions.reverse()
        revision_times = []
        for revision in revisions:
            archived_fullpath = script_dir + ('/archives/%s.%s' % (name, revision))
            gzipped_fullpath = archived_fullpath + '.gz'
            if os.path.isfile(archived_fullpath):
                revision_time = time.asctime(time.localtime(os.stat(archived_fullpath).st_mtime))
                revision_times.append(revision_time)
            elif os.path.isfile(gzipped_fullpath):
                revision_time = time.asctime(time.localtime(os.stat(gzipped_fullpath).st_mtime))
                revision_times.append(revision_time)
        if len(revisions) == 0:
            raise web.notfound()
        return renderer.archiveindex(urlroot, name, zip(revisions, revision_times))


class Uploader:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        return renderer.uploader(urlroot)

    def _sanitize_filename(self, fname):
        # prevent any '../' tomfoolery
        fname = os.path.basename(fname)
        # only allow these characters, because we are paranoid.
        allowed_chars = string.ascii_letters + string.digits + '-_.'
        fname = ''.join([ch for ch in fname if ch in allowed_chars])
        # limit the length
        fname = fname[:256-1]
        return fname

    def POST(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        x = web.input(myfile={})
        filename = self._sanitize_filename(x['myfile'].filename)
        if len(filename) == 0:
            raise web.badrequest()
        open(script_dir + ('/uploads/%s' % filename),'w').write(x['myfile'].value)
        raise web.seeother('/uploads/recent')


class Upload:
    def GET(self, name):
        if session.logged_in == False: raise web.seeother('/authenticator')
        if os.path.isfile(script_dir + ('/uploads/%s' % name)):
            web.header('Content-type', mimetypes.guess_type(name)[0])
            return open(script_dir + ('/uploads/%s' % name)).read()
        else:
            raise web.notfound()


class AllUploads:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        uploads = sorted([fname for fname in os.listdir(script_dir + '/uploads/') \
                          if os.path.isfile(script_dir + ('/uploads/%s' % fname)) \
                          and not os.path.islink(script_dir + ('/uploads/%s' % fname))])
        return renderer.alluploads(urlroot, uploads)


class RecentUploads:
    def GET(self):
        if session.logged_in == False: raise web.seeother('/authenticator')
        uploads = [fname for fname in os.listdir(script_dir + '/uploads/') \
                   if os.path.isfile(script_dir + ('/uploads/%s' % fname)) \
                   and not os.path.islink(script_dir + ('/uploads/%s' % fname))]
        revision_mtimes = [os.stat(script_dir + ('/uploads/%s' % fname)).st_mtime \
                           for fname in uploads]
        upload_tuples = sorted(zip(revision_mtimes, uploads), reverse=True)[:20]
        upload_tuples = [(time.asctime(time.localtime(mtime)), fname) \
                         for (mtime,fname) in upload_tuples]
        return renderer.recentuploads(urlroot, upload_tuples)
