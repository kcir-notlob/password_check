
#include <string>
#include <iostream>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <cstring>

using namespace std;


string get_password()
{

    char password[1024];

    static struct termios old_terminal;
    static struct termios new_terminal;

    //get settings of the actual terminal
    tcgetattr(STDIN_FILENO, &old_terminal);

    // do not echo the characters
    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    // set this as the new terminal options
    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

    // get the password
    // the user can add chars and delete if he puts it wrong
    // the input process is done when he hits the enter
    // the \n is stored, we replace it with \0
    if (fgets(password, BUFSIZ, stdin) == NULL)
        password[0] = '\0';
    else
        password[strlen(password)-1] = '\0';


    // go back to the old settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);


    string ret=password;
    return ret;

}


size_t curl_to_string(void *ptr, size_t size, size_t nmemb, void *data)
{
    string *str = (string *) data;
    char *sptr = (char *) ptr;

    for(int x = 0; x < size * nmemb; ++x)
    {
        (*str) += sptr[x];
    }

    return size * nmemb;
}



int main(int argc,char* argv[]){
  
  cout << "enter password:";
  string pw=get_password();
  cout << endl;

 
  int length=pw.size();
  unsigned char digest[SHA_DIGEST_LENGTH];

  SHA_CTX context;
  if(!SHA1_Init(&context)){
        return 1;
  }

  if(!SHA1_Update(&context, (unsigned char*)pw.c_str(), length)){
        return 2;
  }

  if(!SHA1_Final(digest, &context)){
        return 3;
  }
  char mdString[SHA_DIGEST_LENGTH*2+1];
  for(int i=0;i<SHA_DIGEST_LENGTH;i++){
     sprintf(&mdString[i*2], "%02X", (unsigned int)digest[i]);
  }
  string s=mdString;

 CURL * curl;
 CURLcode res;
 curl_global_init(CURL_GLOBAL_DEFAULT);
 curl=curl_easy_init();

  if(!curl){
    cout << "curl lib failed" << endl;
    return 3;
  }

  string data;
  string hash5="";

  hash5+=mdString[0];
  hash5+=mdString[1];
  hash5+=mdString[2];
  hash5+=mdString[3];
  hash5+=mdString[4];

  string url="https://api.pwnedpasswords.com/range/";
  url+=hash5;


  curl_easy_setopt(curl,CURLOPT_URL,url.c_str());
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_to_string);
  curl_easy_setopt(curl,CURLOPT_WRITEDATA,&data);

  //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

  


  res=curl_easy_perform(curl);
  string code="";
  string hash="";
  string count="";
  bool found=false;

  for(int i=0;i<data.size();i++){
    char c=data[i];
    if(c==':'){
      hash=code;
      hash=hash5 + hash;
      code=""; 
    }
    if(c=='\n'){
      count=code;
      code="";
      if(hash==mdString){
        cout << hash << " -->"  <<  count  << endl;
        found=true;
        break;
      }
    }
    else{
      code+=c;
    }
  }


  curl_easy_cleanup(curl); 
  if(!found){
    cout << " no match found for password" << endl;
  }

  return 0;
}
