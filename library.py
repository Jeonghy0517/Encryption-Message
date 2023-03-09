#정규 표현식(Regular Expressions)
#복잡한 문자열을 처리할 때 사용하는 기법
#파이썬뿐 아니라, C, 자바, 문서 작성 프로그램 등 문자열을 처리해야 하는 다양한 상황에서 활용
#파이썬 정규 표현식은 re 표준 라이브러리를 사용

#정규표현식 사용 예시
#1. 개인 정보가 포함된 문서에서 주민번호 뒷자리를 ******* 로 마스킹하고자 할때
#개인 정보 목록
personal_info = '''
김미키 010-3344-5566 Mike@google.com 800905-1033451
김소은 010-5032-1111 Soeun@naver.com 700905-2134567
유한슬 010-2789-1476 Lyu@school.ac.com 931222-1234567
박민철 010 4040 1313 Zoe@school.ac.com 830810-1234567
이민아 010-7777-2222 Kate@google.com 960711-2434567'''

#방법 1. 정규 표현식을 사용하지 않을 경우
'''
1. 공백 문자를 기준으로 전체 텍스트를 나눔 (split 함수 사용)
2. 나눈 단어가 주민 등록 번호 형식인지 조사
3. 주민 등록 번호 형식이라면 뒷자리를 ***로 마스킹
4. 나눈 단어를 다시 조립
'''

result = []
for line in personal_info.split("\n"): #텍스트 나누기1
    word_result = []

    for word in line.split(" "): #텍스트 나누기2
        if len(word) == 14 and word[:6].isdigit() and word[7:].isdigit(): #주민번호 형식인지 조사
            word = word[:6] + "-" + "*******" #뒷자리 마스킹
        word_result.append(word)
    result.append(" ".join(word_result)) #단어 결합

print("\n".join(result))

#방법2. 정규 표현식을 사용할 경우
#숫자6 + 붙임표(-) + 숫자7 (단, 숫자6은 괄호를 사용하여 그룹으로 지정)
import re
pat = re.compile("(\d{6})[-]\d{7}")
print(pat.sub("\g<1>-*******", personal_info)) #g<1> : 주민번호 앞부분 그룹을 의미

#-------------------------------------------------------------------------------------------------------------------
#비밀번호 감추기
#getpass : 사용자가 비밀번호를 입력할 때 이를 화면에 노출하지 않도록 해주는 모듈

#비밀번호 잠금 해제 예제
passwd = 'hyewon0517' #원본 비밀번호

user_input = input("비밀번호를 입력하세요 >>> ")
while user_input != passwd:
    user_input = input("잘못된 비밀번호입니다! 다시 입력 해주세요 >>> ")

print('잠금이 해제되었습니다 !')
print('''
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▓▒▒▒▒▒▒▒▒▓▒▒
   ▒▒▒▓▓▓▓▓▓▓▓▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒''')

#비밀번호 감추기
import getpass

passwd = 'hyewon0517' #원본 비밀번호

# 사용자 입력 비밀번호
user_input = getpass.getpass("비밀번호를 입력하세요 >>> ")

while user_input != passwd:
    # 비밀번호 불일치 메세지
    user_input = getpass.getpass("잘못된 비밀번호입니다! 다시 입력해주세요 >>> ")

print('잠금이 해제되었습니다 !')
print('''
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▓▒▒▒▒▒▒▒▒▓▒▒
   ▒▒▒▓▓▓▓▓▓▓▓▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒''')

#-------------------------------------------------------------------------------------------------------------------
#비밀번호 암호화
#hashlib : 문자열을 해싱(hashing)할 때 사용하는 모듈
#해싱이란 원본 문자열을 알아볼 수 없는 난해한 문자열로 정의하는 방법, 해시값을 조사하여 데이터 변조 여부를 확인하는 것이 주된 목적
#변환된 데이터는 다시 원본 데이터로 복호화가 불가능

#비밀번호 해싱
import hashlib
import getpass

passwd = 'hyewon0517!' #원본 비밀번호

h = hashlib.sha256()
h.update(passwd.encode('utf-8')) #비밀번호 해싱

h_passwd = h.digest()
print(h_passwd) #해싱된 비밀번호

#비밀번호 해싱을 사용한 경우
def passwd_hash(original_passwd):
    h = hashlib.sha256()
    h.update(original_passwd.encode('utf-8'))
    hashed_passwd = h.digest()
    return hashed_passwd

user_input = passwd_hash(getpass.getpass("비밀번호를 입력하세요 >>> "))

while user_input != h_passwd:
    user_input = passwd_hash(getpass.getpass("잘못된 비밀번호 입니다!. 다시 입력해주세요 >>> "))
    print('방금 입력하신 비밀번호는 ... : {}'.format(user_input))

print('잠금이 해제 되었습니다 !')
print('''
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▓▒▒▓▒▒▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒
   ▒▒▓▒▒▒▒▒▒▒▒▓▒▒
   ▒▒▒▓▓▓▓▓▓▓▓▒▒▒
   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒''')

#-------------------------------------------------------------------------------------------------------------------
#메시지 변조 확인
#hmac : 비밀키와 해싱 기술을 사용해 송수신자 간 메시지 변조를 확인할 수 있도록 하는 모듈
#송수신자 간 약속한 비밀키를 사용해서 해싱된 데이터 내용이 같은지 대조하는 원리
#만약 해커 등 제 3자가 메세지를 변조했을 경우, 비밀키로 해싱한 결과가 달라짐

SECRET_KEY = 'HYEWONJEONG' #비밀 키 설정

#[송신] 암호화(해싱) 파일 생성
import hmac
import hashlib

important_message = '아주 중요한 메세지' #송신 메세지 입력

#원본 파일
with open('message.txt', 'w') as f:
    f.write(important_message)

#비밀 키 암호화 파일
with open('message_encrypted.txt', 'w') as f:
    m = hmac.new(SECRET_KEY.encode('utf-8'), important_message.encode('utf-8'),
                 hashlib.sha256)
    f.write(m.hexdigest())

#[수신] 복호화 및 변조 확인
with open('message_encrypted.txt') as f:
    message_encrypted = f.read()

with open('message.txt') as f:
    massage = f.read()
    m = hmac.new(SECRET_KEY.encode('utf-8'), important_message.encode('utf-8'),
                 hashlib.sha256)

    if m.hexdigest() == message_encrypted:
        print("메시지가 변조되지 않았습니다! 안전합니다.")
    else:
        print("변조된 메세지 입니다! 위험합니다.")

#-------------------------------------------------------------------------------------------------------------------
#안전한 난수(정의된 범위 내에서 무작위로 추출된 수) 생성
#secrets: 파이썬 3.6버전부터 추가된 난수 생성 모듈
#random은 보안이나 암호를 목적으로 사용되기에 위험함
import secrets

#8바이트 난수(16자리)
rand8 = secrets.token_hex(8)
print(rand8)

#16바이트 난수(32자리)
rand16 = secrets.token_hex(16)
print(rand16)

#OTP 비밀번호 생성기
import secrets
import string

print(string.digits)

OTP = ''
digit = string.digits
for i in range(6):
    OTP += str(''.join(secrets.choice(digit)))

print(OTP)

#비밀번호 일치 여부 확인(내부 해싱)
#타이밍 공격(timing attack)을 방지 할 수 있는 기능
print(secrets.compare_digest('password123','password123'))

#보안 URL 생성
url = 'https://mywebsite.com/reset=' + secrets.token_urlsafe(7)
print(url)

