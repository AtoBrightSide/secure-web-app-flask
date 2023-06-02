from flask import Blueprint, flash, render_template, redirect, url_for
from flask_login import current_user

from ..decorators import user_login_required
from ..forms import ComplaintForm
from ..models import Complaint

complaint_bp = Blueprint('complaint_blueprint', __name__)


@complaint_bp.route('/', methods=['GET', 'POST'])
@user_login_required
def complaint():
    form = ComplaintForm()
    form.user_id.data = current_user.user_id
    complaints = Complaint.query.filter_by(user_id=current_user.user_id)
    if form.validate_on_submit():
        form.post_complaint()
        flash('Complaint has been successfully posted!', 'success')
        return redirect(url_for('complaint_blueprint.complaint'))
    return render_template('submit_complaint.html', form=form, complaints=[complaint.todict() for complaint in complaints])