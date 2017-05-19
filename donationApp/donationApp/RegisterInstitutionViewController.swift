//
//  RegisterInstitutionViewController.swift
//  donationApp
//
//  Created by Leticia Vieira Fernandes on 14/04/17.
//  Copyright © 2017 PUC. All rights reserved.
//

import UIKit
import Firebase
import SVProgressHUD
import CryptoSwift
import Locksmith

class RegisterInstitutionViewController: UIViewController {
    
    @IBOutlet weak var emailField: UITextField!
    @IBOutlet weak var passwordField: UITextField!
    @IBOutlet weak var confirmPasswordField: UITextField!

    @IBOutlet weak var emailErrorImage: UIImageView!
    @IBOutlet weak var passwordErrorImage: UIImageView!
    @IBOutlet weak var confirmPaswordErrorImage: UIImageView!
    
    let refInstitutions = FIRDatabase.database().reference(withPath: "features")
    let refInstitutionsUsers = FIRDatabase.database().reference(withPath: "institution-users")
    
    var password_aes256 : String = "";
    var password_sha256 : String = "";
    var salt : String = "";

    // MARK: Life Cycle methods
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let tap : UITapGestureRecognizer = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        self.view.addGestureRecognizer(tap)
    }
    
    func dismissKeyboard() {
        view.endEditing(true)
    }

    // MARK: Actions
    @IBAction func registerAction(_ sender: Any) {
        
        if isEmptyFields() {
            return
        }
        
        if !isMatchPasswords() {
            self.showAlert(withTitle: "Atenção!", message: "As senhas digitadas não correspondem.")
            return
        }
           
        if isShortPassword() {
            self.showAlert(withTitle: "Atenção!", message: "A senha deve ter no mínimo 6 caracteres.")
            return
        }
        else {
            // Busca Instituições
            SVProgressHUD.setDefaultStyle(.dark)
            SVProgressHUD.show()
            
            refInstitutions.observe(.value, with: { snapshot in
                
                if let institution = self.findInstitutionInResults(snapshot) {
                    self.register(institution)
                }
                else {
                    SVProgressHUD.dismiss()
                    self.showAlert(withTitle: "Atenção!", message: "\n Não foi possível realizar o cadastro.\n\n Este e-mail não foi encontrado na base de Instituições reconhecidas.")
                }
            })
        }
    }
    
    @IBAction func closePopOver(_ sender: Any) {
        self.dismiss(animated: true, completion: nil)
    }
    
    // MARK: Firebase methods
    func register(_ institution : Institution) {
        
        // M5: Criptografia inadequada
        
        // Criptografia insegura (md5)
        // let password_md5 = md5Hash(self.passwordField.text!)
        
        // Criptografia segura (AES-256)
        password_aes256 = aes256Encryption(self.passwordField.text!)
        
        // Criptografia segura e ideal Hash SHA-256 (PBKDF2)
        salt = randomString()
        let saltAndPassword = salt + self.passwordField.text!
        password_sha256 = sha256SaltHash(saltAndPassword, salt: salt)
        
        FIRAuth.auth()?.createUser(withEmail: self.emailField.text!, password: password_sha256) { (user, error) in
            
            var title : String = ""
            var msg : String = ""
            
            //Error
            if let error = error {
                SVProgressHUD.dismiss()
                print("Firebase: Register Error!")
                title = "Erro"
                msg = error.localizedDescription
            }
            
            //Success
            if let user = user {
                print("Firebase: Register successfull")
                title = "Sucesso"
                msg = "Cadastro realizado com sucesso. "
                
                self.saveSalt()
                self.insertRegisteredUser(institution, uid:user.uid)
            }
            
            let alert = UIAlertController(title: title, message: msg, preferredStyle: .alert)
            let okAction = UIAlertAction(title: "Ok", style: .default, handler: { (okAction) in
                if (error == nil) {
                    self.dismiss(animated: true, completion: nil)
                }
            })
            
            alert.addAction(okAction)
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    func findInstitutionInResults(_ snapshot : FIRDataSnapshot) -> Institution? {
        
        var foundedInstitution : Institution? = nil
        
        for item in snapshot.children {
            let institution = Institution(snapshot: item as! FIRDataSnapshot)
            
            if self.emailField.text == institution.email  {
                foundedInstitution = institution
            }
        }
        return foundedInstitution
    }
    
    //Save registered user in database
    func insertRegisteredUser(_ institution: Institution, uid: String) {
    
        let date = Date()
        let formatter = DateFormatter()
        formatter.dateFormat = "dd/MM/yyyy HH:mm:ss"
        let dateStr = formatter.string(from: date)
    
        let userInstitution = InstitutionUser(uid: uid,
                                          name: institution.name,
                                          info: institution.info,
                                          email: institution.email,
                                          password: password_sha256,
                                          registerDate: dateStr,
                                          contact: institution.contact,
                                          phone: institution.phone,
                                          bank: institution.bank,
                                          agency: institution.agency,
                                          accountNumber: institution.accountNumber,
                                          address: institution.address,
                                          district: institution.district,
                                          city: institution.city,
                                          state: institution.state,
                                          zipCode: institution.zipCode,
                                          group: institution.group)
        
        let userInstitutionRef = self.refInstitutionsUsers.child(userInstitution.uid)
        userInstitutionRef.setValue(userInstitution.toAnyObject())
        
        SVProgressHUD.dismiss()
    }
    
    // MARK: Encryption methods
    func md5Hash(_ password: String) -> String {
        return password.md5()
    }
    
    func aes256Encryption(_ password: String) -> String {
        
        do {
            let key : Array<UInt8> = Array("770A8A65DA156D24EE2A093277530142".utf8)
            let iv  : Array<UInt8> = Array("F5502320F8429037".utf8)
            let bytesPass : Array<UInt8> = Array(password.utf8)
            
            let encrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).encrypt(bytesPass)
            let decrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).decrypt(encrypted)
            
            let encryptedStr = Data(bytes: encrypted).toHexString()
            
            if let decryptedStr = String(data: Data(bytes: decrypted), encoding: .utf8) {
               // do something
            } else {
                print("That's not a valid UTF-8 sequence.")
            }
            
            return encryptedStr
            
        } catch {
            print(error)
        }
        
        return password
    }
    
    func sha256SaltHash(_ password: String, salt: String) -> String {
        
        let bytesPass: Array<UInt8> = Array(password.utf8);
        let salt: Array<UInt8> = Array(salt.utf8)
        
        do {
            let hashed = try PKCS5.PBKDF2(password: bytesPass, salt: salt, iterations: 4096, variant: .sha256).calculate()
            let hashedStr = Data(bytes: hashed).toHexString()
            
            return hashedStr
            
        } catch {
            print (error)
        }
        
        return password
    }
    
    // MARK: Keychain Access method
    func saveSalt() {
        
        do {
            // M2: Dados inseguros
            
            // Writing data to the keychain
            try Locksmith.saveData(data: ["userSalt": self.salt], forUserAccount: self.emailField.text!)
            
//            let preferences = UserDefaults.standard
//            preferences.setValue(self.salt, forKey: "userSalt")
//            preferences.synchronize()
          
        } catch {
            print(error)
        }
    }
    
    // MARK: Private methods
    func randomString() -> String {
        
        let length: Int = randomNumber()
        
        let letters : NSString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        let len = UInt32(letters.length)
        
        var randomString = ""
        
        for _ in 0 ..< length {
            let rand = arc4random_uniform(len)
            var nextChar = letters.character(at: Int(rand))
            randomString += NSString(characters: &nextChar, length: 1) as String
        }
        
        return randomString
    }
    
    func randomNumber() -> Int
    {
        let MAX : UInt32 = 20
        let MIN : UInt32 = 10
        
        let random_number = Int(arc4random_uniform(MAX) + MIN)
        return random_number
    }
    
    // MARK: Validation methods
    func isEmptyFields() -> Bool {
        
        var isEmpty : Bool = false;
        
        if let email = self.emailField.text, email.isEmpty {
            self.emailErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.emailErrorImage.isHidden = true;
        }
        
        if let password = self.passwordField.text, password.isEmpty {
            self.passwordErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.passwordErrorImage.isHidden = true;
        }
        
        if let confirmPassword = self.confirmPasswordField.text, confirmPassword.isEmpty {
            self.confirmPaswordErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.confirmPaswordErrorImage.isHidden = true;
        }
        
        return isEmpty
    }
    
    func isMatchPasswords() -> Bool {
        
        var  isMatch : Bool = true;
        
        if self.passwordField.text != self.confirmPasswordField.text {
            isMatch = false
        }
        
        return isMatch
    }
    
    func isShortPassword() -> Bool {
        
        var  isShortPassword : Bool = false;
        
        if (self.passwordField.text?.characters.count)! < 6 {
            isShortPassword = true
        }
        
        return isShortPassword
    }
    
    func showAlert(withTitle: String, message: String) {
        
        let alert = UIAlertController(title: title,
                                      message: message,
                                      preferredStyle: .alert)
        
        let okAction = UIAlertAction(title: "Ok",
                                     style: .default)
        
        alert.addAction(okAction)
        self.present(alert, animated: true, completion: nil)
    }
}
