//
//  LoginInstitutionViewController.swift
//  donationApp
//
//  Created by Natalia Sheila Cardoso de Siqueira on 14/04/17.
//  Copyright © 2017 PUC. All rights reserved.
//

import UIKit
import Firebase

class LoginInstitutionViewController: UIViewController {
    
    @IBOutlet weak var emailField: UITextField!
    @IBOutlet weak var passwordField: UITextField!
    
    @IBOutlet weak var emailErrorImage: UIImageView!
    @IBOutlet weak var passwordErrorImage: UIImageView!
    
    @IBOutlet weak var feedbackLabel: UILabel!
    
    let ref = FIRDatabase.database().reference(withPath: "features")

    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    // Entrar
    @IBAction func logIn(_ sender: Any) {
        
        if isEmptyFields() {
            return
        }
        else {
            
            // Falha de segurança
            //loginInsecure()
            
            // Correção
            loginWithFirebase()
        }
    }
    
    func loginInsecure() {
        
        let urlString = "http://tecstarstudio-developer.azurewebsites.net/api/PosGraduacao/Seguranca/logar/" + self.emailField.text! + "/" + self.passwordField.text!
        let url = URL(string: urlString)!
        let session = URLSession.shared
        
        var success = false
        var msg = ""
        
        let task = session.dataTask(with: url) { data, response, error in
            
            do {
                
                if let data = data {
                    success = try JSONSerialization.jsonObject(with: data, options: .allowFragments) as! Bool
                }
                
                if success {
                    self.feedbackLabel.isHidden = false
                    self.feedbackLabel.text = "Login realizado com sucesso."
                } else {
                    self.feedbackLabel.isHidden = false
                    self.feedbackLabel.text = "Erro ao realizar login."

                }
            }
            catch let error {
                print("error: \(error)")
                self.feedbackLabel.isHidden = false
                self.feedbackLabel.text = "Erro ao realizar login. (Exception)"

            }
        }
        task.resume()
    }

    func loginWithFirebase() {
        
        FIRAuth.auth()?.signIn(withEmail: self.emailField.text!, password: self.passwordField.text!) { (user, error) in
            
            //Error
            if let error = error {
                print("Firebase: Login Error!")
                self.showAlert(withTitle: "Erro", message: "Erro ao realizar login: " + error.localizedDescription)
                return
            }
            
            //Success
            if let user = user {
                print("Firebase: Login successfull")
                
                // Successo: Entra como Instituição
                let institutionsTabBarController = UIStoryboard(name: "Institutions", bundle:nil).instantiateViewController(withIdentifier: "tabBarControllerID") as! UITabBarController
                let institutionsNavigationController = UINavigationController(rootViewController: institutionsTabBarController)
                let appDelegate = UIApplication.shared.delegate as! AppDelegate
                appDelegate.window?.rootViewController = institutionsNavigationController
            }
        }
    }
    
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
