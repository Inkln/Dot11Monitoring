from flask import request, abort
from flask_login import current_user, login_required

try:
    from ..models import Ap, Client, Auth, DataTransfer
    from ...app import app, db
    from ...app import vendors_provider
except Exception:
    from app.models import Ap, Client, Auth, DataTransfer
    from app import app, db
    from app import vendors_provider


@app.route("/add_result", methods=["POST"])
@login_required
def receive_scanner_result():
    if not current_user.is_collector:
        abort(403)

    result = request.get_json()
    workspace = result["workspace"]

    for ap_mac in result["visible_aps"]:
        data = result["visible_aps"][ap_mac]
        exists = db.session.query(Ap).filter_by(ap_mac=ap_mac, workspace=workspace).first()
        if not exists:
            ap = Ap(
                ap_mac=ap_mac,
                channel=data["channel"],
                essid=data["essid"],
                privacy=data["privacy"],
                workspace=workspace,
                comment=None,
                mac_vendor=vendors_provider.get_vendor_info(ap_mac),
            )
            db.session.add(ap)

    for client_mac in result["visible_clients"]:
        exists = db.session.query(Client).filter_by(client_mac=client_mac, workspace=workspace).first()
        if not exists:
            client = Client(
                client_mac=client_mac,
                mac_vendor=vendors_provider.get_vendor_info(client_mac),
                workspace=workspace,
            )
            db.session.add(client)

    for transfer in result["client_ap_data_transfer"]:
        ap_mac, client_mac, bytes = transfer["ap"], transfer["client"], transfer["bytes"]
        exists = (
            db.session.query(DataTransfer)
            .filter_by(ap_mac=ap_mac, client_mac=client_mac, workspace=workspace)
            .first()
        )

        if not exists:
            new_transfer = DataTransfer(
                ap_mac=ap_mac, client_mac=client_mac, workspace=workspace, bytes=bytes
            )
            db.session.add(new_transfer)
        else:
            exists.bytes += bytes

    for auth in result["client_authorised"]:
        ap_mac, client_mac, stage, tries = auth["ap"], auth["client"], auth["stage"], auth["tries"]
        exists = (
            db.session.query(Auth)
            .filter_by(ap_mac=ap_mac, client_mac=client_mac, workspace=workspace)
            .first()
        )
        if not exists:
            new_auth = Auth(
                ap_mac=ap_mac, client_mac=client_mac, stage=stage, tries=tries, workspace=workspace
            )
            db.session.add(new_auth)
        else:
            if stage == exists.stage:
                exists.tries += tries
            elif stage > exists.stage:
                exists.stage = stage
                exists.tries = tries

    db.session.commit()
    return "OK", 200
