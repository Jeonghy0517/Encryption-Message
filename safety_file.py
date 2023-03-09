#메세지 변조 탐지기 만들기
##진행 순서##
#1. 계좌 정보 생성
#2. 비밀번호 입력
#3. 계좌정보, 비밀번호 암호화
#4. 메세지 변조 탐지기 생성

#1. 계죄 정보 생성 (개인 정보 감추기)
#개인 정보 입력
client_name = input("이름을 입력해주세요 >>> ")
phone_number = input("전화번호를 입력해주세요 ( - 제외 11자리) >>> ")

#주민번호 입력
import getpass
id_number = getpass.getpass("주민번호를 입력해주세요 (- 제외 13자리) >>> ")

#계좌 번호 입력
account_number = input("계좌 번호를 입력해주세요 (- 제외 15자리) >>> ")

#거래 금액 입력
transfer_amount = input("거래 금액을 만원 단위로 입력해 주세요 >>> ")

#입력 번호 하이픈 추가 함수
def number_parser(input_num, option='phone'):
    output_num = ''
    if option=='phone':
        for i in range(0, len(input_num)):
            if i == 2:
                output_num = output_num + (input_num[2] + '-')
            elif i == 6:
                output_num = output_num + (input_num[6] + '-')
            else:
                output_num = output_num + input_num[i]
    elif option=='acount':
        for i in range(0, len(input_num)):
            if i == 4:
                output_num = output_num + (input_num[2] + '-')
            elif i == 9:
                output_num = output_num + (input_num[9] + '-')
            else:
                output_num = output_num + input_num[i]
    elif option=='id':
        for i in range(0, len(input_num)):
            if i == 5:
                output_num = output_num + (input_num[5] + '-')
            else:
                output_num = output_num + input_num[i]
    elif option=='transfer':
        output_num = input_num + '0000 원'
    return output_num

#계좌 파일 생성
import datetime
with open('계좌정보_원본.txt', 'w') as f:
    f.write(f'등록일시 : {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
    f.write(f'고객명 : {client_name}\n')
    f.write(f'전화번호 : {number_parser(phone_number, "phone")}\n')

    #주민번호 뒷자리 숨기기
    import re
    pat = re.compile("(\d{6})[-](\d{7})")
    id_number = pat.sub("\g<1>-*******", number_parser(id_number, "id"))
    f.write(f'주민번호 : {id_number}\n')

    f.write(f'계좌번호 : {number_parser(account_number, "account")}\n')
    f.write(f'거래금액 : {number_parser(transfer_amount, "transfer")}\n')

#2. 비밀번호 입력
import hashlib
import os

#비밀번호(키)
SECRET_KEY = getpass.getpass("비밀번호를 입력해 주세요 >>> ")
with open('passwd.txt', 'w') as f:
    m = hashlib.sha256()
    m.update(SECRET_KEY.encode('utf-8'))
    f.write(m.hexdigest())

#3. 계좌 정보 암호화
import hmac

#계좌 원본
with open('계좌정보_원본.txt') as f:
    message_origin = f.read()

#비밀키를 활용한 계좌 정보 암호화
with open('계좌정보_암호화.txt', 'w') as f:
    m = hmac.new(SECRET_KEY.encode('utf-8'),message_origin.encode('utf-8'),
                 hashlib.sha256)
    f.write(m.hexdigest())

#4. 메세지 변조 확인 탐지기 생성
import hmac
import hashlib

#비밀번호 확인
with open('passwd.txt','r') as f:
    m = hashlib.sha256()

#암호화 계좌 정보
with open('계좌정보_암호화.txt') as f:
    message_encrypted = f.read()

#계좌 원본 메세지와 비교
with open('계좌정보_원본.txt') as f:
    message_origin = f.read()
    m = hmac.new(SECRET_KEY.encode('utf-8'), message_origin.encode('utf-8'),
                 hashlib.sha256)

    if m.hexdigest() == message_encrypted:
        print("계좌 정보가 변조되지 않았습니다. 안전합니다.👍")
    else:
        print("☢☢ 변조된 계좌 정보 입니다! 위험합니다. ☢☢")



