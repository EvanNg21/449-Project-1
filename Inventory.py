from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for

from models import db, InventoryItem

inventory_bp = Blueprint('inventory', __name__)

@inventory_bp.route('/inventory', methods=['GET'])
def get_inventory_items():
    items = InventoryItem.query.all()
    return jsonify([{
        "id": item.id,
        "name": item.name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    }for item in items])

@inventory_bp.route('/inventory/create', methods=['POST'])
def create_inventory_item():
    data = request.json
    if not all(key in data for key in ['name', 'description', 'quantity', 'price']):
        return jsonify({"error": "Missing required fields"}), 400
    try:
        new_item = InventoryItem(
            name=data['name'], 
            description=data['description'], 
            quantity=data['quantity'], 
            price=data['price']
        )
        db.session.add(new_item)
        db.session.commit()
        return jsonify({"id": new_item.id, "name": new_item.name, "description": new_item.description, "quantity": new_item.quantity, "price": new_item.price, "message": "Inventory Item Created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@inventory_bp.route('/inventory/delete/<int:item_id>', methods=['DELETE'])
def delete_iventory_item(item_id):
    try:
        item = InventoryItem.query.get(item_id)
        if item is None:
            return jsonify({"error": "Inventory Item not found"}), 404
        db.session.delete(item)
        db.session.commit()
        return jsonify({"message": "Inventory Item Deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@inventory_bp.route('/inventory/update/<int:item_id>', methods=['PUT'])
def update_inventory_item(item_id):
    data = request.json
    try:
        item = InventoryItem.query.get(item_id)
        if item is None:
            return jsonify({"error": "Inventory Item not found"}), 404
        
        if 'name' in data:
            item.name = data['name']
        if 'description' in data:
            item.description = data['description']
        if 'quantity' in data:
            item.quantity = data['quantity']
        if 'price' in data:
            item.price = data['price']
        db.session.commit()

        return jsonify({"id": item.id, "name": item.name, "description": item.description, "quantity": item.quantity, "price": item.price, "message": "Inventory Item Updated"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        