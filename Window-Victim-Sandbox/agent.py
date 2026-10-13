from flask import Flask, request, jsonify
import subprocess, os

app = Flask(__name__)

@app.route("/execute", methods=["POST"])
def execute():
	if "file" not in request.files:
		return jsonify({"status": "error", "behavior": "no file provided in request"}), 400
	uploaded = request.files["file"]
	desktop = os.path.join(os.environ["USEPROFILE"], "Desktop")
	save_path = os.path.join(desktop, "incoming_payload.exe")
	uploaded.save(save_path)
	try:
		subprocess.run([save_path], timeout = 10, check=False)
		behavior = "file executed, monitored for 10 seconds"
		dropped_file = os.path.join(desktop, "YOU_HAVE_BEEN_COMPROMISED.txt")
		if os.path.exists(dropped_file):
			behavior += "; file dropped on Desktop, network request attempted"
		status = "executed"
	except subprocess.TimeoutExpired:
		behavior = "process did not exit within 10 seconds (killed)"
		status = "executed_timeout"
	except Exception as e:
		behavior = f"execution error: {e}"
		status = "error"
	return jsonify({"status": status, "behavior": behavior})

@app.route("/health", methods=["GET"])
def health():
	return jsonify({"status": "ok"})

if __name__=="__main__":
	app.run(host="0.0.0.0", port=5000)