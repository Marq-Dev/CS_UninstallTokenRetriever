import tkinter as tk
from falconpy import SensorUpdatePolicy, Hosts
 
# Function for querying the CrowdStrike API
def query_api():
 
    # Get content from entry box widget
    cs_client = str(client_field.get())
    cs_secret = str(secret_field.get())
    cs_host = str(host_field.get())
    cs_comment = str(comment_field.get())
    
    # Sets the Client ID and Secret for the API endpoints
    hosts_endpoint = Hosts(client_id=cs_client, client_secret=cs_secret)
    sensor_endpoint = SensorUpdatePolicy(client_id=cs_client, client_secret=cs_secret)

    # Queries the API using the Device Hostname
    # Response returned as a dict, which gets filtered down using keys
    cs_aid = hosts_endpoint.query_devices_by_filter(filter=f"hostname:'{cs_host}*'")["body"]["resources"][0]

    # Queries the API using the Agent ID and submits a comment for audit logs
    cs_token = sensor_endpoint.reveal_uninstall_token(audit_message=cs_comment, device_id=cs_aid)["body"]["resources"][0]["uninstall_token"]

    # Inserts the response_token value in the entry box widget.
    token_field.insert(0, cs_token)
 
# Function for clearing the contents of all entry box widgets
def clear_all():
 
    # Deletes all content inside entry box widgets
    client_field.delete(0, 'end')
    secret_field.delete(0, 'end')
    host_field.delete(0, 'end')
    comment_field.delete(0, 'end')
    token_field.delete(0, 'end')
   
    # Sets focus on the client_field entry box widget
    client_field.focus_set()

# Main function that draws the window and widgets
if __name__ == "__main__":
   
    # Creates a GUI window
    root = tk.Tk()
   
    # Sets the background color of GUI window
    root.configure(background = 'white')

    # Sets the name of GUI window
    root.title("CrowdStrike Uninstall Token Retriever")

    # Sets the scale relative to other widgets
    root.rowconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)
    root.rowconfigure(2, weight=1)
    root.rowconfigure(3, weight=1)
    root.rowconfigure(4, weight=1)
    root.rowconfigure(5, weight=1)
    root.rowconfigure(6, weight=1)
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=1)
       
    # Creates label widgets
    label_1 = tk.Label(root, text = "API Client : ", fg = 'black', bg = 'white')
    label_2 = tk.Label(root, text = "API Secret : ", fg = 'black', bg = 'white')
    label_3 = tk.Label(root, text = "Hostname : ", fg = 'black', bg = 'white')
    label_4 = tk.Label(root, text = "Audit Comment : ", fg = 'black', bg = 'white')
    label_5 = tk.Label(root, text = "Uninstall Token : ", fg = 'black', bg = 'white')
 
    # Grid method is used for placing the widgets at respective positions in table like structure
    label_1.grid(row = 0, column = 0, padx = 10, pady = 10, sticky="NSEW")
    label_2.grid(row = 1, column = 0, padx = 10, pady = 10, sticky="NSEW")
    label_3.grid(row = 2, column = 0, padx = 10, pady = 10, sticky="NSEW")
    label_4.grid(row = 3, column = 0, padx = 10, pady = 10, sticky="NSEW")
    label_5.grid(row = 5, column = 0, padx = 10, pady = 10, sticky="NSEW")

    # Creates entry box widgets for filling or typing the information
    client_field = tk.Entry(root)
    secret_field = tk.Entry(root)
    host_field = tk.Entry(root)
    comment_field = tk.Entry(root)
    token_field = tk.Entry(root)
 
    client_field.grid(row = 0, column = 1, padx = 10, pady = 10, sticky="EW")
    secret_field.grid(row = 1, column = 1, padx = 10, pady = 10, sticky="EW")
    host_field.grid(row = 2, column = 1, padx = 10, pady = 10, sticky="EW")
    comment_field.grid(row = 3, column = 1, padx = 10, pady = 10, sticky="EW")
    token_field.grid(row = 5, column = 1, padx = 10, pady = 10, sticky="EW")

    # Creates button widgets linked to the query_api and clear_all functions
    button_1 = tk.Button(root, text = "Submit", bg = "white", fg = "black", command = query_api)
    button_2 = tk.Button(root, text = "Clear", bg = "white", fg = "black", command = clear_all)

    button_1.grid(row = 4, column = 1, pady = 10)
    button_2.grid(row = 6, column = 1, pady = 10)
    
    # Starts the GUI
    root.mainloop()