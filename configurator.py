from ast import arg
import json
import pathlib
import sys
from click import option
import requests
import re
import os
import yaml
import logging
import traceback
import hashlib
import base64
import time
import getopt
import argparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# USERNAME = os.environ.get("USERNAME", "axxes-admin")
# PASSWORD = os.environ.get("PASSWORD", "admin")
# GITEA_URL = os.environ.get("GITEA_URL", "https://gitea.axxes.com")
# VERIFY_CERT = os.environ.get("VERIFY_CERT", "true").lower() in [
#     'true', '1', 't', 'y', 'yes', 'ja', 'j']
# TOKEN = os.environ.get("TOKEN", None)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CURRENT_DIR = os.getcwd()
# CONFIG_FILE = os.environ.get("CONFIG_FILE", None)

DEFAULT_OPTIONS_FILES = [
    os.path.join(SCRIPT_DIR, ".config.yaml"),
    os.path.join(SCRIPT_DIR, ".config.yml"),
    os.path.join(SCRIPT_DIR, ".config.json"),
]

DEFAULT_OPTIONS = dict(
    url="http://127.0.0.1:3000",
    verify_cert=True
)


# if not CONFIG_FILE and os.path.isfile("/home/sander/git/axxes-local-k8s/.TEMP/gitea_config.yaml"):
#     CONFIG_FILE = "/home/sander/git/axxes-local-k8s/.TEMP/gitea_config.yaml"
#     GITEA_URL = "https://gitea.axxes.com"
#     VERIFY_CERT = False
#     TOKEN = "e569eee01320512b387974d618ec54439dada6f2"

# gitea_auth = (USERNAME, PASSWORD)
gitea_default_header = {
    "Content-Type": "application/json", "accept": "application/json"}

# logging.basicConfig(format='%(process)d-%(levelname)s-%(message)s')
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
# Remove old token


def validate_url(url):
    if url is None:
        return False
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        # domain...
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return regex.match(url) is not None


def ssh_sha256_fingerprint(pub_key):
    match = re.match(r'[\S]+ +([\S]+)', pub_key)
    if match:
        b64pubkey = match.group(1)
        sha256 = hashlib.sha256()
        sha256.update(base64.b64decode(b64pubkey))
        hash_sha256 = sha256.digest()
        return "SHA256:%s" % base64.b64encode(hash_sha256).decode().rstrip("=")


class GiteaRepo:
    TOKEN_NAME = "gitea_repo_python"

    @classmethod
    def connection_test(cls, url, verify=True):
        try:
            test_url = "%s/api/v1/version" % (url.rstrip("/"))
            r = requests.get(url=test_url, verify=verify)
            r.json()
        except:
            return False
        return True

    def __init__(self, url, username, password, cert_verify=True, token=None, token_name=None) -> None:
        self.url = url
        self.username = username
        self.cert_verify = cert_verify
        self._token_name = token_name or GiteaRepo.TOKEN_NAME
        if not token:
            _id, self.token = self.new_token(username, password)
        else:
            self.token = token

    @property
    def auth(self):
        pass

    def new_token(self, username, password):
        old_token_id = self.get_token_id(
            username, password)
        if old_token_id:
            logging.info("Remove old token (id=%s,name=%s",
                         old_token_id, self._token_name)
            self.remove_token(username, password)

        url = "%s/api/v1/users/%s/tokens" % (self.url, username)
        header = gitea_default_header
        data = {"name": self._token_name}
        r = requests.post(url=url, verify=self.cert_verify, json=data,
                          headers=header, auth=(username, password))
        r_json = r.json()
        token_id = r_json.get("id")
        token = r_json.get("sha1")
        return token_id, token

    def get_token_id(self, username, password):
        try:
            url = "%s/api/v1/users/%s/tokens" % (self.url, username)
            header = gitea_default_header
            r = requests.get(url=url, verify=self.cert_verify,
                             headers=header, auth=(username, password))

            for user_token in r.json():
                if user_token.get("name") == self._token_name:
                    return user_token.get("id")
        except:
            traceback.print_exc()

        return None

    def remove_token(self, username, password):
        url = "%s/api/v1/users/%s/tokens/%s" % (
            self.url, username, self._token_name)
        header = gitea_default_header
        r = requests.delete(url=url, verify=self.cert_verify,
                            headers=header, auth=(username, password))

    def get_organisations(self):
        url = "%s/api/v1/orgs?access_token=%s" % (self.url, self.token)
        header = gitea_default_header
        r = requests.get(url=url, verify=self.url, headers=header)
        return r.json()

    def get_organisation(self, org_name):
        url = "%s/api/v1/orgs/%s?access_token=%s" % (
            self.url, org_name, self.token)
        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify, headers=header)
        r_json = r.json()
        if r_json.get("id"):
            return r_json
        return None

    def create_organisation(self, name, description="", full_name="", website="", location="", visibility="public", repo_admin_change_team_access=True):
        url = "%s/api/v1/orgs?access_token=%s" % (self.url, self.token)

        if visibility.lower() not in ("public", "limited", "private"):
            raise ValueError(
                "Invalid value for 'visibility'. Visibility must be one of [public,limited,private]")

        if website != "" and not validate_url(website):
            raise ValueError("Invalid value for 'website'.")

        if self.get_organisation(name):
            raise ValueError("Organisation '%s' already exists" % name)

        header = gitea_default_header
        data = {
            "description": description,
            "full_name": full_name,
            "location": location,
            "repo_admin_change_team_access": repo_admin_change_team_access,
            "username": name,
            "visibility": visibility,
            "website": website
        }
        r = requests.post(url=url, verify=self.cert_verify,
                          headers=header, json=data)
        return r.json()

    def update_organisation(self, name, **kwargs):
        url = "%s/api/v1/orgs/%s?access_token=%s" % (
            self.url, name, self.token)

        if "visibility" in kwargs and kwargs.get("visibility").lower() not in ("public", "limited", "private"):
            raise ValueError(
                "Invalid value for 'visibility'. Visibility must be one of [public,limited,private]")

        if kwargs.get("website") != "" and kwargs.get("website") is not None and not validate_url(kwargs.get("website")):
            raise ValueError("Invalid value for 'website'.")

        header = gitea_default_header
        data = {}
        for p in ("description", "visibility", "website", "full_name", "location", "repo_admin_change_team_access"):
            if p in kwargs:
                data[p] = kwargs.get(p)

        r = requests.patch(url=url, verify=self.cert_verify,
                           headers=header, json=data)
        return r.json()

    def delete_organisation(self, name):
        url = "%s/api/v1/orgs/%s?access_token=%s" % (
            self.url, name, self.token)
        header = gitea_default_header
        r = requests.delete(url=url, verify=self.cert_verify,
                            headers=header)
        return r.status_code >= 200 and r.status_code < 300

    def get_users(self):
        url = "%s/api/v1/admin/users?access_token=%s" % (self, self.token)
        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify,
                         headers=header)
        return r.json()

    def get_user(self, username):
        url = "%s/api/v1/users/%s?access_token=%s" % (
            self.url, username, self.token)
        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify,
                         headers=header)
        r_json = r.json()
        return r_json if r_json.get("id") else None

    def create_user(self, username, email, **kwargs):
        url = "%s/api/v1/admin/users?access_token=%s" % (self.url, self.token)
        header = gitea_default_header
        data = dict(username=username, email=email)
        data["password"] = kwargs.get("default_password") or "changeme"
        data["must_change_password"] = True

        for p in ("full_name", "login_name", "send_notify", "source_id",  "visibility"):
            if p in kwargs:
                data[p] = kwargs.get(p)
        r = requests.post(url=url, verify=self.cert_verify,
                          headers=header,  json=data)
        return r.json()

    def update_user(self, login_name,  **kwargs):
        url = "%s/api/v1/admin/users/%s?access_token=%s" % (
            self.url, login_name, self.token)

        header = gitea_default_header
        data = dict(login_name=login_name)

        for p in ('active', 'admin', 'allow_create_organization', 'allow_git_hook', 'allow_import_local', 'description', 'email', 'full_name', 'location', 'max_repo_creation', 'prohibit_login', 'restricted', 'visibility', 'website'):
            if p in kwargs:
                data[p] = kwargs.get(p)

        r = requests.patch(url=url, verify=self.cert_verify,
                           headers=header,  json=data)
        return r.json()

    def get_organisation_team(self, org_name, team_name):
        url = "%s/api/v1/orgs/%s/teams/search?access_token=%s&q=%s" % (
            self.url, org_name, self.token, team_name)
        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify,
                         headers=header)
        r_json = r.json()
        for team in r_json.get("data", []):
            if team.get("name") == team_name:
                return team

        return None

    def get_team_members_by_team_id(self, team_id):
        url = "%s/api/v1/teams/%s/members?access_token=%s" % (
            self.url, team_id, self.token)

        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify,
                         headers=header)
        return r.json() if r.status_code == 200 else None

    def create_team(self, org_name, team_name, **kwargs):
        url = "%s/api/v1/orgs/%s/teams?access_token=%s" % (
            self.url, org_name, self.token)

        header = gitea_default_header
        data = dict(name=team_name)

        for p in ('can_create_org_repo', 'description', 'includes_all_repositories', 'permission', 'units'):
            if p in kwargs:
                data[p] = kwargs.get(p)
        r = requests.post(url=url, verify=self.cert_verify,
                          headers=header,  json=data)
        r_json = r.json()
        return r_json

    def update_team(self, org_name, team_name, **kwargs):
        team = self.get_organisation_team(org_name, team_name)
        team_id = team.get("id")
        url = "%s/api/v1/teams/%s?access_token=%s" % (
            self.url, team_id, self.token)

        header = gitea_default_header
        data = dict(name=team_name)
        for p in ('can_create_org_repo', 'description', 'includes_all_repositories', 'permission', 'units'):
            if p in kwargs:
                data[p] = kwargs.get(p)
                logging.debug(
                    "Update propertie (%s) in team (%s) [value: %s]", p, team_name, kwargs.get(p))
        r = requests.patch(url=url, verify=self.cert_verify,
                           headers=header,  json=data)
        r_json = r.json()
        return r_json

    def get_organisation_owners(self, org_name):
        org_owner = self.get_organisation_team(org_name, "Owners")
        org_owner_id = org_owner.get("id")
        return self.get_team_members_by_team_id(org_owner_id)

    def add_member_to_team(self, team_id, username):
        url = "%s/api/v1/teams/%s/members/%s?access_token=%s" % (
            self.url, team_id, username, self.token)

        header = gitea_default_header
        r = requests.put(url=url, verify=self.cert_verify,
                         headers=header)
        return r.status_code >= 200 and r.status_code < 300

    def add_organisation_owner(self, org_name, username):
        org_owner = self.get_organisation_team(org_name, "Owners")
        org_owner_id = org_owner.get("id")
        return self.add_member_to_team(org_owner_id, username)

    def get_organisation_repos(self, org_name):
        url = "%s/api/v1/orgs/%s/repos?access_token=%s" % (
            self.url, org_name, self.token)

        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify, headers=header)
        r_json = r.json()
        return r_json if r_json != [] else None

    def get_repo(self, owner_name, repo_name):
        url = "%s/api/v1/repos/%s/%s?access_token=%s" % (
            self.url, owner_name, repo_name, self.token)

        header = gitea_default_header
        r = requests.get(url=url, verify=self.cert_verify, headers=header)
        r_json = r.json()
        return r_json if "id" in r_json else None

    def get_orgainsation_repo(self, org_name, repo_name):
        return self.get_repo(org_name, repo_name)

    def create_organisation_repo(self, org_name, repo_name, **kwargs):
        url = "%s/api/v1/orgs/%s/repos?access_token=%s" % (
            self.url, org_name, self.token)
        header = gitea_default_header
        data = dict(name=repo_name)
        if "trust_model" in kwargs:
            data["trust_model"] = [tm for tm in kwargs.get("trust_model", []) if tm in (
                "default", "collaborator", "committer", "collaboratorcommitter")]
        for p in ('default_branch', 'description', 'gitignores', 'issue_labels', 'license', 'readme'):
            if p in kwargs and isinstance(kwargs.get(p), str):
                data[p] = kwargs.get(p)
        for p in ('auto_init', 'private', 'template'):
            if p in kwargs and isinstance(kwargs.get(p), str):
                data[p] = kwargs.get(p)
        r = requests.post(url=url, verify=self.cert_verify,
                          headers=header, json=data)
        r_json = r.json()
        return r_json if r_json != [] else None

    def update_repo(self, owner_name, repo_name, **kwargs):
        url = "%s/api/v1/repos/%s/%s?access_token=%s" % (
            self.url, owner_name, repo_name, self.token)

        header = gitea_default_header
        data = dict(name=repo_name)

        for p in ('allow_merge_commits', 'allow_rebase', 'allow_rebase_explicit', 'allow_squash_merge', 'default_branch', 'default_merge_style', 'description', 'has_issues', 'has_projects', 'has_pull_requests', 'has_wiki', 'ignore_whitespace_conflicts', 'private', 'template', 'website'):
            if p in kwargs:
                data[p] = kwargs.get(p)

        r = requests.patch(url=url, verify=self.cert_verify,
                           headers=header,  json=data)
        return r.json()

    def update_organisation_repo(self, org_name, repo_name, **kwargs):
        return self.update_repo(org_name, repo_name, **kwargs)

    def get_repo_keys(self, owner_name, repo_name):
        url = "%s/api/v1/repos/%s/%s/keys?access_token=%s" % (
            self.url, owner_name, repo_name, self.token)
        header = gitea_default_header

        r = requests.get(url=url, verify=self.cert_verify, headers=header)
        r_json = r.json()

        return r_json if isinstance(r_json, list) else None

    def get_repo_key(self, owner_name, repo_name, title):
        keys = self.get_repo_keys(owner_name, repo_name)
        for k in keys:
            if k.get("title") == title:
                return k
        return None

    def get_repo_key_by_fingerprint(self, owner_name, repo_name, fingerprint):
        keys = self.get_repo_keys(owner_name, repo_name)
        for k in keys:
            if k.get("fingerprint", "").split(":")[-1] == fingerprint.split(":")[-1]:
                return k
        return None

    def add_repo_key(self, owner_name, repo_name, key_title, key, read_only=True):
        existing_key = self.get_repo_key(owner_name, repo_name, key_title)
        if existing_key:
            self.delete_repo_key(owner_name, repo_name, existing_key.get("id"))
        url = "%s/api/v1/repos/%s/%s/keys?access_token=%s" % (
            self.url, owner_name, repo_name, self.token)
        header = gitea_default_header
        data = dict(key=key, title=key_title, read_only=read_only)
        r = requests.post(url=url, verify=self.cert_verify,
                          headers=header, json=data)
        r_json = r.json()
        return r_json if "id" in r_json else None

    def delete_repo_key(self, owner_name, repo_name, key_id):
        url = "%s/api/v1/repos/%s/%s/keys/%s?access_token=%s" % (
            self.url, owner_name, repo_name, key_id, self.token)
        header = gitea_default_header
        r = requests.delete(url=url, verify=self.cert_verify, headers=header)
        return r.status_code >= 200 and r.status_code < 300


def parse_arguments():
    main_parser = argparse.ArgumentParser()
    main_parser.add_argument('-a', '--url', action='store', type=str)
    main_parser.add_argument('-u', '--user', action='store', type=str)
    main_parser.add_argument('-p', '--password', action='store', type=str)
    main_parser.add_argument('-t', '--token', action='store', type=str)
    main_parser.add_argument(
        '-k', '--insecure', nargs='?', default=None, const=True)
    main_parser.add_argument(
        '--secure', nargs='?', default=None, const=True)
    main_parser.add_argument('-c', '--config',
                             action='store', type=pathlib.Path)
    args = vars(main_parser.parse_args())
    args["verify_cert"] = False if args.pop(
        "insecure") == True else True if args.pop("secure") == True else None
    return args


def parse_envs():
    envs = {k: v for k, v in os.environ.items() if k.startswith("GITEA_")}
    return dict(
        url=envs.get("GITEA_URL"),
        user=envs.get("GITEA_USER") or envs.get("GITEA_USERNAME"),
        password=envs.get("GITEA_PASSWORD"),
        token=envs.get("GITEA_TOKEN"),
        verify_cert=True if envs.get("GITEA_INSECURE", "none").lower() in ('false', '0', 'f', 'n', 'no', 'nee', 'n') else False if envs.get(
            "GITEA_INSECURE", "none").lower() in ('true', '1', 't', 'y', 'yes', 'ja', 'j') else None,
        config=pathlib.Path(envs.get("GITEA_CONFIG")
                            ) if "GITEA_CONFIG" in envs else None,
    )

def script_options():
    options = DEFAULT_OPTIONS
    options.update({k: v for k, v in parse_envs().items() if v is not None})
    options.update({k: v for k, v in parse_arguments().items() if v is not None})
    return options

class ConfObject(dict):
    ALLOWED_PROPERTIES = {}
    def __init__(self,*args,**kwargs):
        if args and isinstance(args,list):
            if len(args) < 2 and isinstance(args[0],dict):
                self.update(self.__verify_properties(args[0]))
            else:
                raise ValueError("Invalid args for %s object"%type(self))
        else:
            self.update(self.__verify_properties(**kwargs))

    def __verify_properties(self,**kwargs):
        verified_properties = {}
        for key,value in kwargs.items():
            if key in self.ALLOWED_PROPERTIES:
                required_value_type = self.ALLOWED_PROPERTIES.get(key)
                if isinstance(required_value_type,type) and isinstance(value,required_value_type):
                    verified_properties[key] = value
                elif required_value_type == bool and isinstance(value,(str,int)):
                    if str(value).lower() in ('yes','true','1','y',"ja","j"):
                        verified_properties[key] = True
                    elif str(value).lower() in ('no','false','0','n',"nee",):
                        verified_properties[key] = False
                    else: 
                        logging.info("Invalid value for '%s' property in %s object"%(key,type(self)))
                elif isinstance(required_value_type,ConfObject.Validator) and required_value_type.validate(value):
                    verified_properties[key] = value
                elif callable(required_value_type) and required_value_type(value):
                    verified_properties[key] = value
                else: 
                    logging.info("Invalid value for '%s' property in %s object"%(key,type(self)))
            else:
                logging.info("Property '%s' not allowed for %s object"%(key,type(self)))
        return verified_properties

    @classmethod
    def ValidWebsite(cls,url):
        if url is None:
            return False
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            # domain...
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return regex.match(url) is not None

    class Validator:
        def validate(self):
            return None,True

    class TypeList:
        def __init__(self,*args,**kwargs):
            if args and isinstance(args,list):
                if len(args) < 2 and isinstance(args[0],dict):
                    self.type = args[0]
                else:
                    raise ValueError("Invalid args for %s object"%type(self))
            else:
                self.type = kwargs

        def validate(self,value):
            if isinstance(self.type,ConfObject.Validator):
                valid_values = []
                valid = True
                for i in value:
                    if isinstance(self.type,ConfObject.Validator):
                        v_valid_value,v_valid = self.type.validate(i)
                    elif isinstance(self.type,type) and isinstance(i,self.type):
                        v_valid_value,v_valid = i,True
                    elif callable(self.type) and self.type(i):
                        v_valid_value,v_valid = i,True
                    else:
                        v_valid_value,v_valid = None,False

                    valid = valid and v_valid
                    if v_valid:
                        valid_values.append(v_valid_value)
                    else:
                        logging.debug("Invalid value of type %s in %s"%(type(i),type(self)))
                return valid_values,valid
            else:
                return all(True for s in value if isinstance(s,self.type))
    
    class TypeBool:
        def __init__(self):
            pass

        def validate(self,value):
            if isinstance(value,bool):
                return value,True
            elif str(value).lower() in ('yes','true','1','y',"ja","j"):
                return True,True
            elif str(value).lower() in ('no','false','0','n',"nee",):
                return False,True
            else: 
                return None,False

    class TypeDict:
        def __init__(self,*args,**kwargs):
            if args and isinstance(args,list):
                if len(args) < 2 and isinstance(args[0],dict):
                    self.type = args[0]
                else:
                    raise ValueError("Invalid args for %s object"%type(self))
            else:
                self.type = kwargs

        def validate(self,value):
            valid = True
            valid_value = {}
            if not isinstance(value,dict):
                raise ValueError("Value need to be a %s"%dict)
            for k,v in value.items():
                if k in self.type:
                    if isinstance(self.type.get(k),ConfObject.Validator):
                        v_valid_value,v_valid = self.type.get(k).validate(v)
                        if v_valid:
                            valid_value[k] = v_valid_value
                        else: 
                            logging.debug("Invalid value for '%s' property in %s object"%(k,type(self)))
                    elif isinstance(self.type.get(k),type) and isinstance(v,self.type.get(k)):
                        valid_value[k] = v
                    elif callable(self.type.get(k)) and self.type.get(k)(value):
                        valid_value[k] = v
                    else:
                        logging.info("Invalid value for '%s' property in %s object"%(k,type(self)))
                else: 
                    valid = False
                    logging.debug("Property '%s' not allowed for %s object"%(k,type(self)))

        

# - username: user1
#     email: user1@example.com
#     default_password: changeme
#     active: true
#     admin: true
#     description: string
#     full_name: string
#     location: string
#     prohibit_login: true
#     restricted: true
#     visibility: string
#     website: https://www.user1.com

class User(ConfObject):
    ALLOWED_PROPERTIES = dict(
        username=str,
        email=str,
        active=bool,
        admin=bool,
        description=str,
        full_name=str,
        location=str,
        prohibit_login=bool,
        restricted=bool,
        visibility=str,
        website=ConfObject.ValidWebsite,
        default_password=str,
        )
    
class Organisation(ConfObject):
    ALLOWED_PROPERTIES = dict(
        name=str,
        description=str,
        full_name=str,
        location=str,
        visibility=str,
        repo_admin_change_team_access=str,
        website=ConfObject.ValidWebsite,
        owners=ConfObject.TypeList(str),
        )    



user = User(username="sdescamps",website="https://test.com",active="no")
org = Organisation(name="axxes",owners="test")
print(user)


sys.exit(1)

if __name__ == "__main__":
    options=script_options()
    logging.info("Start Gitea Configurator")
    logging.info("CONFIG_FILE=%s", options.get("config"))
    logging.info("GITEA_URL=%s", options.get("url"))
    logging.info("VERIFY_CERT=%s", options.get("verify_cert"))
    gitea_config = None
    if not options.get("config") or not os.path.isfile(options.get("config")):
        logging.error("Config file not found")
        sys.exit(1)
    with open(options.get("config"), "r") as file:
        if options.get("config") and options.get("config").suffix in ('.yml','.yaml'):
            gitea_config = yaml.load(file, yaml.FullLoader)
        elif options.get("config") and options.get("config").suffix in (".json"):
            gitea_config = json.load(file)
        else:
            logging.error("Unsupported config file")
            sys.exit(1)

    if gitea_config == {}:
        sys.exit(0)

    timeout = 60*2   # 2 minutes from now
    start_time = time.time()
    while True:
        if GiteaRepo.connection_test(options.get("url"), verify=options.get("verify_cert")):
            break
        elif time.time() > start_time + timeout:
            logging.error(
                "Connection timeout. Can't reach the Gitea API %s" % options.get("url"))
            sys.exit(1)
        logging.info("Gitea API not yet available (%ds)" %
                     (int(time.time()-start_time)))
        time.sleep(5)

    gitea_repo = GiteaRepo(options.get("url"), options.get("user"), options.get("password"),
                           cert_verify=options.get("verify_cert"), token=options.get("token"))

    for user in gitea_config.get("users", []):
        if not isinstance(user.get("username"), str) or not isinstance(user.get("email"), str):
            logging.error("Invalid user: %s", str(user))
        else:
            existing_user = gitea_repo.get_user(user.get("username"))
            if not existing_user:
                kwargs = {}
                for p in ("full_name", "send_notify", "visibility"):
                    if p in user:
                        kwargs[p] = user.get(p)
                existing_user = gitea_repo.create_user(
                    user.get("username"), user.get("email"), **kwargs)
                logging.info("Create User: %s", user.get("username"))
            changed = False
            kwargs = dict()
            if "admin" in user and user.get("admin") != existing_user.get("is_admin"):
                kwargs["admin"] = user.get("admin")
                changed = True
            for p in ('active', 'description', 'full_name', 'location', 'prohibit_login', 'restricted', 'visibility', 'website'):
                if p in user and user.get(p) != existing_user.get(p):
                    kwargs[p] = user.get(p)
                    changed = True
            if changed:
                logging.debug("Modify user %s: %s",
                              user.get("username"), str(kwargs))
                updated_user = gitea_repo.update_user(
                    login_name=existing_user.get("login"), **kwargs)
                logging.info("Update User: %s", user.get("username"))
            else:
                logging.info("User already exists: %s", user.get("username"))

    for org in gitea_config.get("organisations", []):
        if not isinstance(org.get("name"), str):
            logging.error("Invalid organisation: %s", str(org))
        else:
            existing_org = gitea_repo.get_organisation(org.get("name"))
            if not existing_org:
                kwargs = dict(name=org.get("name"))
                for p in ("description", "visibility", "website", "full_name", "location", "repo_admin_change_team_access"):
                    if p in org:
                        kwargs[p] = org.get(p)
                result = gitea_repo.create_organisation(**kwargs)
                if result.get("id"):
                    logging.info("Create Organisation: %s", org.get("name"))
                else:
                    logging.error(
                        "Failed to create Organisation: %s", org.get("name"))
            else:
                changed = False
                kwargs = dict()
                for p in ("description", "visibility", "website", "full_name", "location", "repo_admin_change_team_access"):
                    if p in org and org.get(p) != existing_org.get(p):
                        kwargs[p] = org.get(p)
                        changed = True
                if changed:
                    gitea_repo.update_organisation(org.get("name"), **kwargs)
                    logging.info("Update organisation: %s", org.get("name"))
                else:
                    logging.info(
                        "Organisation already exists: %s", org.get("name"))

        if isinstance(org.get("owners"), list):
            existing_owners = [
                u.get("username") for u in gitea_repo.get_organisation_owners(org.get("name"))]
            for owner in org.get("owners", []):
                if owner not in existing_owners:
                    gitea_repo.add_organisation_owner(org.get("name"))
                    logging.info(
                        "Add %s to Owners of organisation %s", owner, org.get("name"))
                else:
                    logging.info(
                        "User %s already owner in organisation %s", owner, org.get("name"))

        if isinstance(org.get("teams"), list):
            for team in org.get("teams"):
                units = [t for t in team.get("units", []) if t in (
                    "repo.code", "repo.issues", "repo.ext_issues", "repo.wiki", "repo.pulls", "repo.releases", "repo.projects", "repo.ext_wiki")]
                existing_team = gitea_repo.get_organisation_team(
                    org.get("name"), team.get("name"))
                if not existing_team:
                    kwargs = {k: v for k, v in team.items() if k in (
                        'can_create_org_repo', 'description', 'includes_all_repositories', 'permission')}
                    kwargs["units"] = units
                    existing_team = gitea_repo.create_team(
                        org.get("name"), team.get("name"), **kwargs)
                    logging.info("Create team: %s" % team.get("name"))
                else:
                    changed = False
                    kwargs = dict()
                    for p in ('can_create_org_repo', 'description', 'includes_all_repositories', 'permission'):
                        if p in team and team.get(p) != existing_team.get(p):
                            kwargs[p] = team.get(p)
                            changed = True
                    if team.get("permissions") != "admin" and set(existing_team.get("units") or set([])) != set(units):
                        kwargs["units"] = units
                        changed = True
                    if changed:
                        gitea_repo.update_team(
                            org.get("name"), team.get("name"), **kwargs)
                        logging.info("Updated team: %s" % team.get("name"))
                    else:
                        logging.info("Team already exists: %s" %
                                     team.get("name"))
                current_team_members = [m.get(
                    "username") for m in gitea_repo.get_team_members_by_team_id(existing_team.get("id"))]
                for member in team.get("members", []):
                    if member not in current_team_members:
                        gitea_repo.add_member_to_team(
                            existing_team.get("id"), member)
                        logging.info("Add %s to team %s" %
                                     (member, team.get("name")))
                    else:
                        logging.info("%s already member of team %s" %
                                     (member, team.get("name")))

        if isinstance(org.get("repositories"), list):
            for repo in org.get("repositories"):
                existing_repo = gitea_repo.get_orgainsation_repo(
                    org.get("name"), repo.get("name"))
                if not existing_repo:
                    kwargs = {k: v for k, v in repo.items() if k in ('default_branch', 'description',
                                                                     'gitignores', 'issue_labels', 'license', 'readme', 'auto_init', 'private', 'template')}
                    if "trust_model" in kwargs:
                        kwargs["trust_model"] = [tm for tm in repo.get("trust_model", []) if tm in (
                            "default", "collaborator", "committer", "collaboratorcommitter")]
                    existing_repo = gitea_repo.create_organisation_repo(
                        org.get("name"), repo.get("name"), **kwargs)
                    logging.info("Create repo: %s" % repo.get("name"))

                changed = False
                kwargs = dict()
                for p in ('allow_merge_commits', 'allow_rebase', 'allow_rebase_explicit', 'allow_squash_merge', 'default_branch', 'default_merge_style', 'description', 'has_issues', 'has_projects', 'has_pull_requests', 'has_wiki', 'ignore_whitespace_conflicts', 'private', 'template', 'website'):
                    if p in repo and repo.get(p) != existing_repo.get(p):
                        kwargs[p] = repo.get(p)
                        changed = True
                if changed:
                    gitea_repo.update_organisation_repo(
                        org.get("name"), repo.get("name"), **kwargs)
                    logging.info("Update repository: %s" % repo.get("name"))
                else:
                    logging.info("repository already exists: %s" %
                                 repo.get("name"))

                if isinstance(repo.get("ssh_authorized_keys"), list):
                    for ssh_key in repo.get("ssh_authorized_keys", []):
                        fingerprint = ssh_sha256_fingerprint(
                            ssh_key.get("key"))
                        if fingerprint is None:
                            logging.error(
                                "Can't calculate fingerprint of ssh key: %s..." % ssh_key.get("key", "")[1:20])
                        existing_key = gitea_repo.get_repo_key_by_fingerprint(
                            org.get("name"), repo.get("name"), fingerprint=fingerprint)
                        if not existing_key:
                            gitea_repo.add_repo_key(org.get("name"), repo.get("name"), ssh_key.get(
                                "name"), ssh_key.get("key"), read_only=ssh_key.get("read_only", True))
                            logging.info(
                                "Add SSH key (fingerprint:%s) to repo %s", fingerprint, repo.get("name"))
                        else:
                            if ssh_key.get("read_only", True) != existing_key.get("read_only") or (ssh_key.get("title") or ssh_key.get("name")) != existing_key.get("title"):
                                gitea_repo.delete_repo_key(org.get("name"), repo.get(
                                    "name"), key_id=existing_key.get("id"))
                                gitea_repo.add_repo_key(org.get("name"), repo.get("name"), ssh_key.get(
                                    "name"), ssh_key.get("key"), read_only=ssh_key.get("read_only", True))
                                logging.info(
                                    "Renew SSH key (fingerprint:%s) to repo %s", fingerprint, repo.get("name"))
                            else:
                                logging.info(
                                    "SSH key (fingerprint:%s) already addes to repo %s", fingerprint, repo.get("name"))


# print(get_organisations(gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT))
# print(get_organisation("qsdf", gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT))
# print(get_organisation("Axxes", gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT))

# print([o.get("username") for o in get_organisations(gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT)])
# for org in ["org1",'org10', 'org12', 'org2', 'org3', 'org4', 'org5', 'org6', 'org7', 'org8']:
#     if get_organisation(org, gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT):
#         delete_organisation(org, gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT)
# print([o.get("username") for o in get_organisations(gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT)])

# print(yaml.dump(get_users(gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT),indent=2))
# print(get_user("sander.descamps",gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT))
# print(get_organisation_owners("test-org",gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT))
# print([u.get("username") for u in get_organisation_owners("test-org",gitea_url=GITEA_URL, token=token, verify=VERIFY_CERT)])
# print(ssh_sha256_fingerprint("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcCCdKM54uf0iOr2bNtHltzfkcL32F/uhVq/UtBbqjMe2SSF7NCo1Vt1zjmCC2IqvpQtbJh2K4/1jCEVrK1O2Y59ARxKOEBCFEXHC2p17kdrNmMowh9GQsgM+6bCUSqqmahFf8//htQVanRQWVrIUy63oMEYS/rs8T+IOmZD7AOgc3TGd3gKxQQO9bPw/PyCrUFo7YtHWzgpWJvOhGzAflD3yd2a7ppr/btYy3YtACNgXC+ug2jfw9yoZ70ir7FMRzcNK9E5Dlnc83/+Lu3YYLRuHeLyoKB9iBYEw5grxBu7NaZoR5JR/OvpaELvrlPaeBQJ2dODRtwZbl9lApaAXB"))
