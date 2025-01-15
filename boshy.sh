#!/bin/bash



API_KEY="ENTER YOUR API KEY HERE"
#enter you api key here you can get it from  https://www.virustotal.com/gui/my-apikey
echo -e "\033[34mwelcome to boshy network analyzer\033[0m"



ipfile=""
has_ip_file="n"
savefile="VTresult.txt"

read -p "Do you already have a file with public IP addresses? (y/n): " has_ip_file

if [[ "$has_ip_file" == "y" || "$has_ip_file" == "Y" ]]; then

  read -p "Enter the file containing IP addresses (.txt file): " ipfile
 if [[ -f "$ipfile" && "$ipfile" == *.txt ]]; then
  echo -e "\033[34mProceeding with analysis...\033[0m"
else
  echo -e "\033[31mError: File '$ipfile' not found or not a .txt file.\033[0m"
  exit 1
fi

elif [[ "$has_ip_file" == "n" || "$has_ip_file" == "N" ]]; then
  read -p "Enter the pcap file you want to analyze: " input_file
  if [[ ! -f "$input_file" ]]; then
    echo -e "\033[31mError: File '$input_file' not found!\033[0m"
    exit 1
     elif ! file "$input_file" | grep -q -i "capture"; then
echo -e "\033[31mError: File '$input_file' is not recognized as a network capture file!\033[0m"

    exit 1
  else
    echo "File '$input_file' found. Proceeding with analysis..."
  fi

else

echo -e "\033[31minvalid choice!!....please enter 'y' or 'n'\033[0m"
  exit 1
fi


  ipfile="publicip.txt"
  echo "Analyzing the file......"
  tshark -r "$input_file" -T fields -e ip.src -e ip.dst | \
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
  grep -v -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.)' | \
  sort -u > "$ipfile"

  if [ -s "$ipfile" ]; then
    echo "Analysis complete! Public IP addresses have been saved in '$ipfile'."
    echo ""
    else
    echo -e "\033[32mSomething went wrong!\033[0m"
  fi



while read -r ip; do
  echo "checking for: $ip"
  raw_response=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ip" --header "x-apikey: $API_KEY")

  # Extract malicious, suspicious, and reputation values
result_of_malicious=$(echo "$raw_response" | grep -oP '"last_analysis_stats":\s*\{"malicious":\s*[0-9]+' | grep -oP '"malicious":\s*[0-9]+' | grep -oP '[0-9]+' | tr -d '[:space:]')



result_of_suspicious=$(echo "$raw_response" | grep -oP '"suspicious":\s*[0-9]+' | grep -oP '[0-9]+' | tr -d '[:space:]')




result_of_reputation=$(echo "$raw_response" | awk -F'"reputation":' '{print $2}' | awk '{print $1}' | tr -d ',[:space:]')





  if [ "$result_of_malicious" -gt 0 ] || [ "$result_of_reputation" -lt 0 ] || [ "$result_of_suspicious" -gt 0 ]; then
echo -e "the IP: \033[31m$ip\033[0m is Malicious - Malicious score: $result_of_malicious, Suspicious score: $result_of_suspicious, Reputation score: $result_of_reputation" >> $savefile

elif [ "$result_of_malicious" -le 0 ] && [ "$result_of_reputation" -ge 0 ] && [ "$result_of_suspicious" -le 0 ]; then
echo -e "the IP: \033[32m$ip\033[0m - No issues detected, Reputation: $result_of_reputation" >> $savefile
  else
echo -e "Error: couldn't find a result for \033[38;5;214m$ip\033[0m" >> $savefile


  fi
  
  
  # Please note that you can only send 4 lookups/min, DO NOT CHANGE THE SLEEP TIME unless you are a premium VirusTotal user
  sleep 15
done < "$ipfile"
echo -e "\033[34Analysis complete! Results saved in $savefile\033[0m"
