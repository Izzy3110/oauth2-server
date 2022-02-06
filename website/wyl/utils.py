import os
from urllib.parse import urlsplit, parse_qs
from ..models import db
from ..models import Scopes as ScopesDB
from datetime import datetime
import time


def build_new_qry_str(referer):
    url_s = urlsplit(referer)
    qry_ = {}
    qry = parse_qs(url_s.query)
    for key, val in qry.items():
        if key != "login":
            qry_[key] = val[0]

    qry_str_items = []
    for key, val in qry_.items():
        qry_str_items.append(key + "=" + val)
    return "&".join(qry_str_items)


class Scopes(object):
    method_names = ["POST", "GET"]
    scope_files = ["website/routes.py"]

    def get_scopes(self):
        commit_needed = False
        scope_urls = []
        for scope_file in self.scope_files:
            lines = open(scope_file).read().splitlines()
            lines_bp = []
            for line_i in range(0, len(lines)):
                line = lines[line_i]
                if line.startswith("@bp"):
                    if "@require_oauth" in lines[line_i + 1]:
                        lines_a_ = []
                        for line_ in line.lstrip("@bp.route('").split("/"):
                            if len(line_) > 0:
                                if "'" in line_:
                                    lines_a_.append(line_.split("'")[0])
                                else:
                                    lines_a_.append(line_)
                        scope_method = "GET"
                        spl_ = line.replace('"', "'").split("'")
                        for item_i_ in range(0, len(spl_)):
                            item_ = spl_[item_i_]
                            if "methods" in item_:
                                if spl_[item_i_ + 1] in self.method_names:
                                    scope_method = spl_[item_i_ + 1]
                        scope_name = lines[line_i + 1].replace('"', "'").split("'")[1]
                        base_ = None
                        section_ = None
                        if ":" in scope_name:
                            splitted_ = scope_name.split(":")
                            base_ = splitted_[0]
                            section_ = splitted_[1]
                        scope_url_ = "/" + "/".join(lines_a_)
                        scope_in_db = ScopesDB.query.filter_by(scope=scope_name).first()
                        if scope_in_db is None:
                            print("is none")
                            scope = ScopesDB(base=base_, section=section_, url=scope_url_, methods=scope_method, scope=scope_name, date_first_seen=datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f'))
                            db.session.add(scope)
                            if not commit_needed:
                                commit_needed = True
                        else:
                            print("existsing: "+scope_name)

                        new_scope = {
                            "base": base_,
                            "section": section_,
                            "url": scope_url_,
                            "scope": scope_name,
                            "method": scope_method
                        }
                        lines_bp.append(new_scope)
                    else:
                        if "def" in lines[line_i + 1]:
                            method_ = "GET"
                            if "methods" in line:
                                tmp_ = line.replace('"',"'").split("'")
                                methods_arr = []
                                for i_a in range(0, len(tmp_)):
                                    current_ = tmp_[i_a]
                                    if "methods" in current_:
                                        method_ = tmp_[int(i_a+1)]
                                        methods_arr.append(method_)
                                        try:
                                            second_method = tmp_[int(i_a+3)]
                                            methods_arr.append(second_method)
                                        except IndexError:
                                            pass
                            scope_urls.append({"url": line.split("'")[1], "method": method_, "methods": ",".join(methods_arr)})
        if commit_needed:
            db.session.commit()
        return {"scopes": lines_bp, "urls": scope_urls}
