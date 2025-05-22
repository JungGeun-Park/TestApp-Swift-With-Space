//
//  ViewController.swift
//  TestApp_Swift
//
//  Created by 박정근 on 2023/02/20.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    private let greetingLabel = UILabel()
    private let rotateButton = UIButton(type: .system)

//    @objc func rotateButtonTapped() {
//        if let scene = self.view.window?.windowScene {
//            scene.requestGeometryUpdate(.iOS(interfaceOrientations: .landscapeRight)){ (error) -> Void in } }
//    }

    override func viewDidAppear( _ animated: Bool )
    {
        super.viewDidAppear( animated );

        greetingLabel.text = "Hello, World!"
        greetingLabel.textColor = .darkGray
        greetingLabel.textAlignment = .center
        greetingLabel.frame = CGRect(
            x: 20,
            y: view.safeAreaInsets.top + 100,
            width: view.bounds.width - 40,
            height: 50
        )
        view.addSubview(greetingLabel)
        
        // 버튼 생성 및 속성 설정
//        rotateButton.setTitle("가로로 회전", for: .normal)
//        rotateButton.setTitleColor(.white, for: .normal)
//        rotateButton.backgroundColor = .systemBlue
//        rotateButton.layer.cornerRadius = 8
//        rotateButton.frame = CGRect(
//            x: (view.bounds.width - 200) / 2,
//            y: view.bounds.height / 2 - 25,
//            width: 200,
//            height: 50
//        )
//        rotateButton.addTarget(self, action: #selector(rotateButtonTapped), for: .touchUpInside)
//        rotateButton.autoresizingMask = [.flexibleLeftMargin, .flexibleRightMargin, .flexibleTopMargin, .flexibleBottomMargin]
//        view.addSubview(rotateButton)

        //############################################################## AppSealing Code-Part BEGIN: DO NOT MODIFY THIS LINE !!!
        #if true  //--------------------------------------- APPSEALING-GetDeviceID [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated1: AppSealingInterface = AppSealingInterface();
        let _appSealingDeviceID_auto_generated = String.init( cString: _instAppSealing_auto_generated1._GetAppSealingDeviceID() );
        let _appsealing_msg1 = "\n\n* AppSealing Device ID : ";
        print( _appsealing_msg1 + _appSealingDeviceID_auto_generated + "\n\n" );
        #endif    //--------------------------------------- APPSEALING-GetDeviceID [END] : DO NOT REMOVE THIS COMMENT !!!

        #if true  //--------------------------------------- APPSEALING-SecurityThreadCheck [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated2: AppSealingInterface = AppSealingInterface();
        let _appsealing_tamper_auto_generated: Int32 = _instAppSealing_auto_generated2._IsAbnormalEnvironmentDetected();
        
        print("Tamper Detection Result: \(_appsealing_tamper_auto_generated)")
        
        if ( _appsealing_tamper_auto_generated > 0 )
        {
            var _appsealing_msg2 = "Abnormal Environment Detected !!";
            if ( _appsealing_tamper_auto_generated & DETECTED_JAILBROKEN ) > 0
                { _appsealing_msg2 += "\n - Jailbroken"; }
            if ( _appsealing_tamper_auto_generated & DETECTED_DRM_DECRYPTED ) > 0
                { _appsealing_msg2 += "\n - Executable is not encrypted"; }
            if ( _appsealing_tamper_auto_generated & DETECTED_DEBUG_ATTACHED ) > 0
                { _appsealing_msg2 += "\n - App is debugged"; }
            if ( _appsealing_tamper_auto_generated & ( DETECTED_HASH_INFO_CORRUPTED | DETECTED_HASH_MODIFIED )) > 0
                { _appsealing_msg2 += "\n - App integrity corrupted"; }
            if ( _appsealing_tamper_auto_generated & ( DETECTED_CODESIGN_CORRUPTED | DETECTED_EXECUTABLE_CORRUPTED )) > 0
                { _appsealing_msg2 += "\n - App executable has corrupted"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_CERTIFICATE_CHANGED ) > 0 )
                { _appsealing_msg2 += "\n - App has re-signed"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_BLACKLIST_CORRUPTED ) > 0 )
                { _appsealing_msg2 += "\n - Blacklist/Whitelist has corrupted or missing"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_CHEAT_TOOL ) > 0 )
                { _appsealing_msg2 += "\n - Cheat tool has detected"; }
            
            print("Tamper Detection Result: \(_appsealing_msg2)")
            let _alertController_auto_generated = UIAlertController(title: "AppSealing", message: _appsealing_msg2, preferredStyle: .alert );
            _alertController_auto_generated.addAction(UIAlertAction(title: "Confirm", style: .default,
                                    handler: { (action:UIAlertAction!) -> Void in
            #if !DEBUG   // Debug mode does not kill app even if security threat has found
                                                _exit(0);
            #endif
//                                if let scene = self.view.window?.windowScene {
//                                scene.requestGeometryUpdate(.iOS(interfaceOrientations: .landscapeRight)){ (error) -> Void in } }
                                                } ));
                    self.present( _alertController_auto_generated, animated: true, completion: nil );
        }
        #endif    //--------------------------------------- APPSEALING-SecurityThreadCheck [END] : DO NOT REMOVE THIS COMMENT !!!
        #if true  //--------------------------------------- APPSEALING-GetCredential [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated3: AppSealingInterface = AppSealingInterface();
        let _appSealingCredential_auto_generated = String.init( cString: _instAppSealing_auto_generated3._GetEncryptedCredential() );
        let _appsealing_msg3_1 = "AppSealing Credential (Initial): \(_appSealingCredential_auto_generated)"
        NSLog("%@", _appsealing_msg3_1)
        
        // 첫 번째 출력
    
        // 10초 후 두 번째 출력
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            let _appSealingCredential_auto_generated2 = String.init(cString: _instAppSealing_auto_generated3._GetEncryptedCredential())
            let _appsealing_msg3_2 = "AppSealing Credential (After 10s): \(_appSealingCredential_auto_generated2)"
            NSLog("%@", _appsealing_msg3_2)
        }
    
        // 20초 후 세 번째 출력
        DispatchQueue.main.asyncAfter(deadline: .now() + 40) {
            let _appSealingCredential_auto_generated3 = String.init(cString: _instAppSealing_auto_generated3._GetEncryptedCredential())
            let _appsealing_msg3_3 = "AppSealing Credential (After 20s): \(_appSealingCredential_auto_generated3)"
            NSLog("%@", _appsealing_msg3_3)
        }
        
        // use thie credential value in your authentication function
        #endif    //--------------------------------------- APPSEALING-GetDeviceID [END] : DO NOT REMOVE THIS COMMENT !!!

        #if true //--------------------------------------- APPSEALING-AntiSwizzling [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
//        AppSealingInterface._NotifySwizzlingDetected( { ( msg: String? ) -> () in
//            let alertController = UIAlertController( title: "AppSealing Security", message: msg, preferredStyle: .alert )
//            alertController.addAction( UIAlertAction( title: "Confirm", style: .default,
//                                    handler: { ( action:UIAlertAction! ) -> Void in
//                                #if !DEBUG
//                                    exit( 0 );
//                            #endif
//            } ));
//            self.present( alertController, animated: true, completion: nil );
//        } );
        #endif    //--------------------------------------- APPSEALING-GetDeviceID [END] : DO NOT REMOVE THIS COMMENT !!!
        //############################################################## AppSealing Code-Part END: DO NOT MODIFY THIS LINE !!!

    }
}


