//
//  RequestsViewController.swift
//  donationApp
//
//  Created by Letícia Fernandes on 11/03/17.
//  Copyright © 2017 PUC. All rights reserved.
//

import UIKit

class RequestsViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        
        self.tabBarController?.title = "Pedidos"
        self.tabBarController?.navigationItem.rightBarButtonItem = nil
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    

    /*
    // MARK: - Navigation

    // In a storyboard-based application, you will often want to do a little preparation before navigation
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        // Get the new view controller using segue.destinationViewController.
        // Pass the selected object to the new view controller.
    }
    */

}
