#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re



class MainHandler(webapp2.RequestHandler):
    def build_form(self, username, password, verify_password, email, username_error, password_error, verify_password_error, email_error):
        form = """<html><head></head><body><form method='post'>
        <label>Username</label><input type="text" name="username" value="%(USERNAME)s">%(USERNAME_ERROR)s<br />
        <label>Password<label><input type="text" name="password" value="%(PASSWORD)s">%(PASSWORD_ERROR)s<br />
        <label>Verify Password</label><input type="text" name="verify_password" value="%(VERIFY_PASSWORD)s">%(VERIFY_PASSWORD_ERROR)s<br />
        <label>Email (optional)</label><input type="text" name="email" value="%(EMAIL)s">%(EMAIL_ERROR)s<br />
        <input type="submit" />
        </form></body></html>""" % {"USERNAME": username,
                             "PASSWORD": password,
                             "VERIFY_PASSWORD": verify_password,
                             "EMAIL": email,
                             "USERNAME_ERROR": username_error,
                             "PASSWORD_ERROR": password_error,
                             "VERIFY_PASSWORD_ERROR": verify_password_error,
                             "EMAIL_ERROR": email_error
                             }
        
        return form


    def get(self):
        content = self.build_form('','','','','','','','')
        self.response.out.write(content)
        
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        ver_password = self.request.get("verify_password")
        email = self.request.get("email")
        is_errored = False
        
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        
        def valid_username(username):
            if USER_RE.match(username):
                return True
        
        def valid_password(password):
            if PASSWORD_RE.match(password):
                return True
        
        def verify_password(password, ver_password):
            return password == ver_password
        
        def valid_email(email):
            if email != '':
                if EMAIL_RE.match(email):
                    return True
                else:
                    return False
        
        
        if valid_username(username):
            username_error = ''
        else:
            username_error = "That is not a valid username."
            is_errored = True
            
        if valid_password(password):
            password_error = ''
        else:
            password_error = "That is not a valid password."
            is_errored = True
            
        if verify_password(password, ver_password):
            verify_password_error = ''
        else:
            verify_password_error = "Password do not match."
            is_errored = True
            
        if valid_email(email):
            email_error = ''
        if valid_email(email) == False:
            email_error = "That is not a valid email."
            is_errored = True
        if valid_email(email) == None:
            email_error = ''
            
         
         
        if is_errored:   
            content = self.build_form(username, '', '', email, username_error, password_error, verify_password_error, email_error)
            self.response.out.write(content)
        else:
            self.response.out.write("Welcome, %(USERNAME)s!" %{"USERNAME": username})



app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
