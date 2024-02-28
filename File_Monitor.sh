#!/bin/bash

logPath="/home/vboxuser/Desktop/UNAUTH_DETECTED.txt"

ipPort_Path="/home/vboxuser/Desktop/IP_PORTS_CONNECTIONS.txt"

audKey="unauthorized_file_access"

authUser="vboxuser"

desktopPath="/home/vboxuser/Desktop"

knownHash="a2191fecff6888643fd9ba6c5b626dca5b1182c55f5091b7c1f3834eee08ae84"


#Function to change password to all user accounts on the system

change_all_passwords() {
    local newPassword="BREACH!" # Replace with your desired password
    for user in $(awk -F':' '$3 >= 1000 {print $1}' /etc/passwd); do
        if [ "$user" != "nobody" ] && [ "$user" != "nologin" ]; then
            echo "$user:$newPassword" | sudo chpasswd
        fi
    done
}



# Function to calculate and compare file hash

calculate_compare_hash() {
    local fileTo_Check="/home/vboxuser/Desktop/Super Secret Folder/Confidential  Document - Authorized User's Only.odt"
    local hashOutput_Path="/home/vboxuser/Desktop/HASH_COMPARISON.txt"
    
    # Calculate the current hash of the file
    local currentHash=$(sha256sum "$fileTo_Check" | awk '{print $1}')
    
    # Compare and output to file
    echo "Known Hash: $knownHash" > "$hashOutput_Path"
    echo "Current Hash: $currentHash" >> "$hashOutput_Path"
    
    if [ "$currentHash" == "$knownHash" ]; then
        echo "Hash Match: YES" >> "$hashOutput_Path"
    else
        echo "Hash Match: NO" >> "$hashOutput_Path"
    fi
}





#Function to record and store command history of all users except the authorized user

command_history() {
	
	for userHome in /home/* /root; do
		username=$(basename "$userHome")
		commandFile="$userHome/.bash_history"
		outputCommand_File="$desktopPath/${username}_history.txt"
		
		#Checks if user is not authorized user and if command history file exits
		if [[ "$username" != $authUser && -f "$commandFile" ]]; then 
			#Copies Command History to a txt file
			echo "Command history for $username:" > "$outputCommand_File"
			cat "$commandFile" >> "$outputCommand_File"
			echo "End of $username's command history" >> "$outputCommand_File"
		
		fi
		
	done


}

#Function to record established connections to the linux OS

record_connections() {

	echo "Network Connections:" > "$ipPort_Path"
	ss -tn | awk 'NR>1 {print $4 " to " $5}' >> "$ipPort_Path"



}

# Function to disconnect the network


disconnect_network() {
    #names of all network interfaces
    for interface in $(ip link show | awk -F: '$0 !~ "lo|vir|^[^0-9]"{print $2;getline}'); do
        # Disable all interfaces
        sudo ip link set $interface down
    done
}




#Function for logging out all users


logout_users() {
	who | awk '{print $2}' | while read session; do
		if [[ "$session" != *"/"* ]]; then
			pkill -KILL -t "$session"
		fi
	done


}


# Print a message indicating that the monitoring has started
echo "Monitoring For Unauthorized Access..."


#Actively Monitor The Audit Log For Changes To The Confidential File

tail -f /var/log/audit/audit.log | grep --line-buffered "$audKey" |

while read line; do
	if [[ $line != *"$authUser"* ]]; then
		echo "$(date): Unauthorized Access Detected: $line" >> "$logPath"
		
		#Record Command History if breach is detected
		command_history
		
		#Record and Compare hashses if breach is detected
		calculate_compare_hash
		
		#Record Net Connections if breach is detected
		record_connections
		
		# Disconnect from the network if breach is detected
       		disconnect_network
       		
       		#Change the password of all users on the system if breach is detected
       		change_all_passwords
       		
		#Logout all users if breach is detected
		logout_users
	fi
	
done




