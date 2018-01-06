from app import app
from flask import request, jsonify

import models

@app.route('/encounters/patient/<int:patient_id>', methods = ['GET', 'POST'])
def encounter_patient(patient_id):
    data = request.get_json()
    if request.method == 'GET':
        result = models.get_encounters(patient_id, data)
        if result is None:
            return {'status': 400, 'message': 'Clinical data for patient {} not found'.format(patient_id)}
        mediatorResponse = jsonify(result)
        mediatorResponse.headers["Content-Type"] = 'application/json+openhim'
        return mediatorResponse
    else:
        data = request.get_json()
        data['patient_id'] = patient_id
        result = models.save_encounter(data)
        if result is None:
            result = {'status': 400, 'message': 'Encounter not inserted. Insufficient data.'}
        mediator_response = jsonify(result)
        mediator_response.headers["Content-Type"] = 'application/json+openhim'
        return mediator_response

@app.route('/encounters/<int:encounter_id>', methods = ['GET'])
def encounter(encounter_id):
    data = request.get_json()
    result = models.get_encounter(encounter_id, data)
    if result is None:
        return {'status': 400, 'message': 'Encounter with id={} not found'.format(encounter_id)}
    mediator_response = jsonify(result)
    mediator_response.headers["Content-Type"] = 'application/json+openhim'
    return mediator_response

@app.route('/encounters/', methods = ['POST'])
def save_encounter():
    data = request.get_json()
    result = models.save_encounter(data)
    if result is None:
        result = {'status': 400, 'message': 'Insufficient Data'}
    mediator_response = jsonify(result)
    mediator_response.headers["Content-Type"] = 'application/json+openhim'
    return mediator_response, 201

