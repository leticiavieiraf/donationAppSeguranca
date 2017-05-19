//
//  LoginInstitutionViewController.swift
//  donationApp
//
//  Created by Leticia Vieira Fernandes on 14/04/17.
//  Copyright © 2017 PUC. All rights reserved.

import UIKit
import Firebase
import SVProgressHUD
import CryptoSwift
import Locksmith

class LoginInstitutionViewController: UIViewController {
    
    @IBOutlet weak var emailField: UITextField!
    @IBOutlet weak var passwordField: UITextField!
    
    @IBOutlet weak var emailErrorImage: UIImageView!
    @IBOutlet weak var passwordErrorImage: UIImageView!
    
    @IBOutlet weak var feedbackLabel: UILabel!
    
    let ref = FIRDatabase.database().reference(withPath: "features")

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
    @IBAction func logIn(_ sender: Any) {
        
        if isEmptyFields() {
            return
        }
        else {
            // M4: Autenticação insegura
            
            // Falha de segurança
            // loginInsecure()
            
            // Correção
            loginWithFirebase()
        }
    }
    
    // MARK: Firebase methods
    func loginInsecure() {
        
        // M3: Comunicação insegura
        
        let urlString = "http://tecstarstudio-developer.azurewebsites.net/api/PosGraduacao/Seguranca/logar/" + self.emailField.text! + "/" + self.passwordField.text!
        let url = URL(string: urlString)!
        let session = URLSession.shared
        var success = false
        
        SVProgressHUD.setDefaultStyle(.dark)
        SVProgressHUD.show()
        let task = session.dataTask(with: url) { data, response, error in
            
            do {
                if let data = data {
                    success = try JSONSerialization.jsonObject(with: data, options: .allowFragments) as! Bool
                }
                
                if success {
                    self.feedbackLabel.text = "Login realizado com sucesso."
                } else {
                    self.feedbackLabel.text = "Erro ao realizar login."
                }
                SVProgressHUD.dismiss(withDelay: 9.0)
                
            }
            catch let error {
                SVProgressHUD.dismiss(withDelay: 9.0)
                print("error: \(error)")
                self.feedbackLabel.text = "Erro ao realizar login. (Exception)"
            }
        }
        task.resume()
    }

    func loginWithFirebase() {
        
        SVProgressHUD.setDefaultStyle(.dark)
        SVProgressHUD.show()
        
        // Criptografia segura (AES)
        let password_aes = aes256Encryption(self.passwordField.text!)
        
        // Criptografia segura e ideal Hash SHA-256 (PBKDF2)
        let salt = loadSalt()
        let saltAndPassword = salt + self.passwordField.text!
        let password_sha256 = sha256SaltHash(saltAndPassword, salt: salt)
        
        FIRAuth.auth()?.signIn(withEmail: self.emailField.text!, password: password_sha256) { (user, error) in
            
            SVProgressHUD.dismiss()
            
            //Error
            if let error = error {
                print("Firebase: Login Error!")
                self.showAlert(withTitle: "Erro", message: "Erro ao realizar login: " + error.localizedDescription)
                return
            }
            
            //Success
            if let user = user {
                print("Firebase: Login successfull")
                
                // Redireciona para o storyboard de Instituição
                let institutionsTabBarController = UIStoryboard(name: "Institutions", bundle:nil).instantiateViewController(withIdentifier: "tabBarControllerID") as! UITabBarController
                let institutionsNavigationController = UINavigationController(rootViewController: institutionsTabBarController)
                let appDelegate = UIApplication.shared.delegate as! AppDelegate
                appDelegate.window?.rootViewController = institutionsNavigationController
            }
        }
    }
    
    // MARK: Encryption methods
    func aes256Encryption(_ password: String) -> String {
        
        do {
            let key: Array<UInt8> = Array("770A8A65DA156D24EE2A093277530142".utf8)
            let iv: Array<UInt8> = Array("F5502320F8429037".utf8)
            let bytesPass: Array<UInt8> = Array(password.utf8)
            
            let encrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).encrypt(bytesPass);
            let decrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).decrypt(encrypted)
            
            let encryptedStr = Data(bytes: encrypted).toHexString()
            print(encryptedStr)
            
            if let decryptedStr = String(data: Data(bytes: decrypted), encoding: .utf8) {
                
                // M7: Questões de qualidade do código do cliente
                //print(decryptedStr)
            } else {
                //print("That's not a valid UTF-8 sequence.")
            }
            
            return encryptedStr
            
        } catch {
            print(error)
        }
        
        return password;
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
    func loadSalt() -> String {
        
        // Reading data from the keychain
        if let saltDictionary = Locksmith.loadDataForUserAccount(userAccount: self.emailField.text!) {
            if let userSalt = saltDictionary["userSalt"] {
              return userSalt as! String
            }
        }
        
         return ""
    }
    
    // MARK: Validation methods
    func isEmptyFields() -> Bool {
        
        var isEmpty: Bool = false;
        
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
        
        return isEmpty
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

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
}
